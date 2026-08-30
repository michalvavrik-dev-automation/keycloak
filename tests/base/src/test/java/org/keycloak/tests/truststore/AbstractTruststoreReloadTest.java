package org.keycloak.tests.truststore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.PemUtils;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.truststore.SystemTruststoreReload;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

abstract class AbstractTruststoreReloadTest {

    static final Path TRUSTSTORE_FILE = Path.of(System.getProperty("java.io.tmpdir"), "kc-it-system-truststore.pem");

    private static final char[] STORE_PASSWORD = "password".toCharArray();
    private static final byte[] UNRELATED_CERTIFICATE = readResource("org/keycloak/tests/ssl/smtp-server.pem");
    private static final AtomicInteger CA_SEQUENCE = new AtomicInteger();

    static {
        try {
            Files.write(TRUSTSTORE_FILE, UNRELATED_CERTIFICATE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @InjectRunOnServer(permittedPackages = "org.keycloak.tests.truststore")
    RunOnServerClient runOnServer;

    @BeforeEach
    void resetSystemTruststoreToUnrelatedCertificate() throws IOException {
        Files.write(TRUSTSTORE_FILE, UNRELATED_CERTIFICATE);
        triggerReload();
    }

    @Test
    void outboundHttpClientPicksUpRotatedCaAfterReload() throws Exception {
        try (TlsPeer peer = startTlsPeer()) {
            String url = "https://localhost:" + peer.port() + "/";
            assertFalse(httpClientTrusts(url), "peer ca must not be trusted before reload");

            rotateSystemTruststoreTo(peer.certificateAuthority);
            triggerReload();

            awaitTrusted(() -> httpClientTrusts(url));
        }
    }

    @Test
    void ldapsSocketFactoryPicksUpRotatedCaAfterReload() throws Exception {
        try (TlsPeer peer = startTlsPeer()) {
            assertFalse(ldapsSocketFactoryTrusts(peer.port()), "peer ca must not be trusted before reload");

            rotateSystemTruststoreTo(peer.certificateAuthority);
            triggerReload();

            awaitTrusted(() -> ldapsSocketFactoryTrusts(peer.port()));
        }
    }

    @Test
    void nginxLookupPicksUpRotatedCaAfterReload() throws Exception {
        X509Certificate certificateAuthority = generateCertificateAuthority();
        String subject = certificateAuthority.getSubjectX500Principal().getName();
        assertFalse(nginxLookupTrusts(subject), "peer ca must not be trusted before reload");

        rotateSystemTruststoreTo(certificateAuthority);
        triggerReload();

        awaitTrusted(() -> nginxLookupTrusts(subject));
    }

    private boolean httpClientTrusts(String url) {
        return runOnServer.fetch(session -> {
            try {
                session.getProvider(HttpClientProvider.class).getString(url);
                return Boolean.TRUE;
            } catch (Exception untrusted) {
                return Boolean.FALSE;
            }
        }, Boolean.class);
    }

    private boolean ldapsSocketFactoryTrusts(int port) {
        return runOnServer.fetch(session -> {
            try {
                javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) org.keycloak.truststore.SSLSocketFactory
                        .getDefault().createSocket(InetAddress.getLoopbackAddress().getHostAddress(), port);
                javax.net.ssl.SSLParameters parameters = socket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm(null);
                socket.setSSLParameters(parameters);
                socket.startHandshake();
                socket.close();
                return Boolean.TRUE;
            } catch (Exception untrusted) {
                return Boolean.FALSE;
            }
        }, Boolean.class);
    }

    private boolean nginxLookupTrusts(String subject) {
        return runOnServer.fetch(session -> {
            try {
                var factory = session.getKeycloakSessionFactory()
                        .getProviderFactory(X509ClientCertificateLookup.class, "nginx");
                factory.create(session);
                java.lang.reflect.Field field = factory.getClass().getDeclaredField("trustedRootCerts");
                field.setAccessible(true);
                java.util.Set<?> roots = (java.util.Set<?>) field.get(factory);
                return roots.stream().anyMatch(certificate ->
                        ((X509Certificate) certificate).getSubjectX500Principal().getName().equals(subject));
            } catch (Exception e) {
                return Boolean.FALSE;
            }
        }, Boolean.class);
    }

    private void triggerReload() {
        runOnServer.run(session -> SystemTruststoreReload.reload(session));
    }

    private void awaitTrusted(Callable<Boolean> trusted) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(20))
                .pollInterval(Duration.ofMillis(500))
                .until(trusted);
    }

    private static void rotateSystemTruststoreTo(X509Certificate certificateAuthority) throws IOException {
        Files.writeString(TRUSTSTORE_FILE,
                PemUtils.addCertificateBeginEnd(PemUtils.encodeCertificate(certificateAuthority)));
    }

    private TlsPeer startTlsPeer() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate certificateAuthority = selfSignedCertificate(caKeyPair);
        return new TlsPeer(startHttpsServer(serverKeyStoreSignedBy(caKeyPair, certificateAuthority)),
                certificateAuthority);
    }

    private static X509Certificate generateCertificateAuthority() throws Exception {
        return selfSignedCertificate(generateKeyPair());
    }

    private static X509Certificate selfSignedCertificate(KeyPair caKeyPair) {
        return CryptoIntegration.getProvider().getCertificateUtils()
                .generateV1SelfSignedCertificate(caKeyPair, "Truststore Reload IT CA " + CA_SEQUENCE.incrementAndGet());
    }

    private static KeyStore serverKeyStoreSignedBy(KeyPair caKeyPair, X509Certificate certificateAuthority)
            throws Exception {
        KeyPair serverKeyPair = generateKeyPair();
        X509Certificate serverCertificate = CryptoIntegration.getProvider().getCertificateUtils()
                .generateV3Certificate(serverKeyPair, caKeyPair.getPrivate(), certificateAuthority, "localhost");
        KeyStore keyStore = newKeyStore();
        keyStore.setKeyEntry("server", serverKeyPair.getPrivate(), STORE_PASSWORD,
                new Certificate[] { serverCertificate, certificateAuthority });
        return keyStore;
    }

    private static HttpsServer startHttpsServer(KeyStore serverKeyStore) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(serverKeyStore, STORE_PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream responseBody = exchange.getResponseBody()) {
                responseBody.write(body);
            }
        });
        server.setExecutor(null);
        server.start();
        return server;
    }

    private static KeyStore newKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(
                CryptoIntegration.getProvider().getPreferredGeneratedTrustStoreType().name());
        keyStore.load(null, null);
        return keyStore;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte[] readResource(String resource) {
        try (InputStream stream = AbstractTruststoreReloadTest.class.getClassLoader().getResourceAsStream(resource)) {
            return stream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static final class TlsPeer implements AutoCloseable {

        private final HttpsServer server;
        private final X509Certificate certificateAuthority;

        private TlsPeer(HttpsServer server, X509Certificate certificateAuthority) {
            this.server = server;
            this.certificateAuthority = certificateAuthority;
        }

        private int port() {
            return server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
