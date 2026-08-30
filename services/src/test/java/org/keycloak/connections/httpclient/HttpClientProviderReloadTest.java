package org.keycloak.connections.httpclient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
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
import javax.security.auth.x500.X500Principal;

import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;
import org.keycloak.truststore.FileTruststoreProviderFactory;
import org.keycloak.truststore.SystemTruststoreReload;
import org.keycloak.truststore.TruststoreProvider;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HttpClientProviderReloadTest {

    private static final char[] PASSWORD = "password".toCharArray();

    private CryptoProvider originalCryptoProvider;
    private ResteasyKeycloakSessionFactory sessionFactory;

    @Before
    public void useDefaultCryptoProvider() {
        originalCryptoProvider = CryptoIntegration.isInitialised() ? CryptoIntegration.getProvider() : null;
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
        Profile.defaults();
    }

    @After
    public void restoreCryptoProvider() {
        if (sessionFactory != null) {
            sessionFactory.close();
        }
        CryptoIntegration.setProvider(originalCryptoProvider);
    }

    @Test
    public void outboundHttpClientPicksUpRotatedCaAfterReload() throws Exception {
        KeyPair caKeyA = generateKeyPair();
        X509Certificate caCertA = selfSignedCa(caKeyA, "Test CA A");
        KeyPair caKeyB = generateKeyPair();
        X509Certificate caCertB = selfSignedCa(caKeyB, "Test CA B");

        HttpsServer serverSignedByA = startHttpsServer(serverKeyStoreSignedBy(caKeyA, caCertA));
        HttpsServer serverSignedByB = startHttpsServer(serverKeyStoreSignedBy(caKeyB, caCertB));
        try {
            sessionFactory = new ResteasyKeycloakSessionFactory();
            sessionFactory.init();
            KeycloakSession session = new ResteasyKeycloakSession(sessionFactory);
            fileTruststoreProviderFactory().setProvider(providerTrusting(caCertA));

            assertTrue("A-signed server should be trusted before reload",
                    outboundCallSucceeds(session, portOf(serverSignedByA)));
            assertFalse("B-signed server should not be trusted before reload",
                    outboundCallSucceeds(session, portOf(serverSignedByB)));

            SystemTruststoreReload.propagate(providerTrusting(caCertB));

            assertTrue("B-signed server should be trusted after reload",
                    outboundCallSucceeds(session, portOf(serverSignedByB)));
        } finally {
            serverSignedByA.stop(0);
            serverSignedByB.stop(0);
        }
    }

    private static boolean outboundCallSucceeds(KeycloakSession session, int port) throws IOException {
        try (CloseableHttpResponse response = session.getProvider(HttpClientProvider.class).getHttpClient()
                .execute(new HttpGet("https://localhost:" + port + "/"))) {
            return response.getStatusLine().getStatusCode() == 200;
        } catch (SSLException untrusted) {
            return false;
        }
    }

    private FileTruststoreProviderFactory fileTruststoreProviderFactory() {
        return (FileTruststoreProviderFactory) sessionFactory.getProviderFactory(TruststoreProvider.class, "file");
    }

    private static int portOf(HttpsServer server) {
        return server.getAddress().getPort();
    }

    private static HttpsServer startHttpsServer(KeyStore serverKeyStore) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(serverKeyStore, PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.setExecutor(null);
        server.start();
        return server;
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

    private static final class FixedTruststoreProvider implements TruststoreProvider {

        private final KeyStore truststore;

        private FixedTruststoreProvider(KeyStore truststore) {
            this.truststore = truststore;
        }

        @Override
        public HostnameVerificationPolicy getPolicy() {
            return HostnameVerificationPolicy.ANY;
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
}
