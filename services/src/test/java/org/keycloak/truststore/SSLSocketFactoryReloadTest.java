package org.keycloak.truststore;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.crypto.def.DefaultCryptoProvider;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SSLSocketFactoryReloadTest {

    private static final char[] PASSWORD = "password".toCharArray();

    private CryptoProvider originalCryptoProvider;

    @Before
    public void setUpCryptoAndClearCachedFactory() throws Exception {
        originalCryptoProvider = CryptoIntegration.isInitialised() ? CryptoIntegration.getProvider() : null;
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
        clearCachedFactory();
    }

    @After
    public void restoreCrypto() throws Exception {
        clearCachedFactory();
        TruststoreProviderSingleton.set(null);
        CryptoIntegration.setProvider(originalCryptoProvider);
    }

    @Test
    public void ldapsPicksUpRotatedCaAfterReload() throws Exception {
        KeyPair caKeyA = generateKeyPair();
        X509Certificate caCertA = selfSignedCa(caKeyA, "Test CA A");
        KeyPair caKeyB = generateKeyPair();
        X509Certificate caCertB = selfSignedCa(caKeyB, "Test CA B");

        try (LocalTlsServer serverSignedByA = new LocalTlsServer(serverKeyStoreSignedBy(caKeyA, caCertA));
             LocalTlsServer serverSignedByB = new LocalTlsServer(serverKeyStoreSignedBy(caKeyB, caCertB))) {

            TruststoreProviderSingleton.set(providerTrusting(caCertA));

            assertTrue(ldapsClientTrusts(serverSignedByA.port));
            assertFalse(ldapsClientTrusts(serverSignedByB.port));

            SystemTruststoreReload.propagate(providerTrusting(caCertB));

            assertTrue(ldapsClientTrusts(serverSignedByB.port));
        }
    }

    private static boolean ldapsClientTrusts(int port) throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault()
                .createSocket(InetAddress.getLoopbackAddress().getHostAddress(), port)) {
            trustOnlyWithoutHostnameCheck(socket);
            socket.startHandshake();
            return true;
        } catch (SSLException untrusted) {
            return false;
        }
    }

    private static void trustOnlyWithoutHostnameCheck(SSLSocket socket) {
        SSLParameters params = socket.getSSLParameters();
        params.setEndpointIdentificationAlgorithm(null);
        socket.setSSLParameters(params);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSignedCa(KeyPair caKeyPair, String commonName) {
        return CryptoIntegration.getProvider().getCertificateUtils().generateV1SelfSignedCertificate(caKeyPair, commonName);
    }

    private static KeyStore serverKeyStoreSignedBy(KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        KeyPair serverKeyPair = generateKeyPair();
        X509Certificate serverCert = CryptoIntegration.getProvider().getCertificateUtils()
                .generateV3Certificate(serverKeyPair, caKeyPair.getPrivate(), caCert, "localhost");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", serverKeyPair.getPrivate(), PASSWORD, new Certificate[] { serverCert, caCert });
        return keyStore;
    }

    private static TruststoreProvider providerTrusting(X509Certificate ca) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        return new FixedTruststoreProvider(trustStore);
    }

    private static void clearCachedFactory() throws Exception {
        Field instance = SSLSocketFactory.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private static final class FixedTruststoreProvider implements TruststoreProvider {

        private final KeyStore truststore;

        private FixedTruststoreProvider(KeyStore truststore) {
            this.truststore = truststore;
        }

        @Override
        public HostnameVerificationPolicy getPolicy() {
            return HostnameVerificationPolicy.DEFAULT;
        }

        @Override
        public javax.net.ssl.SSLSocketFactory getSSLSocketFactory() {
            return null;
        }

        @Override
        public KeyStore getTruststore() {
            return truststore;
        }

        @Override
        public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
            return Map.of();
        }

        @Override
        public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
            return Map.of();
        }

        @Override
        public KeyStore getHttpsTruststore() {
            return truststore;
        }

        @Override
        public Map<X500Principal, List<X509Certificate>> getHttpsRootCertificates() {
            return Map.of();
        }

        @Override
        public Map<X500Principal, List<X509Certificate>> getHttpsIntermediateCertificates() {
            return Map.of();
        }

        @Override
        public void close() {
        }
    }

    private static final class LocalTlsServer implements AutoCloseable {

        private final SSLServerSocket serverSocket;
        private final Thread acceptThread;
        private volatile boolean running = true;
        final int port;

        private LocalTlsServer(KeyStore keyStore) throws Exception {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, PASSWORD);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagerFactory.getKeyManagers(), null, null);
            serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 0, InetAddress.getLoopbackAddress());
            port = serverSocket.getLocalPort();
            acceptThread = new Thread(this::acceptUntilClosed, "local-tls-server-" + port);
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        private void acceptUntilClosed() {
            while (running) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                    socket.getInputStream().read();
                } catch (Exception clientRejectedOrClosing) {
                }
            }
        }

        @Override
        public void close() {
            running = false;
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
    }
}
