package org.keycloak.tests.truststore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.PemUtils;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.truststore.SystemTruststoreReload;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.PfxOptions;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class AbstractTruststoreReloadTest {

    static final Path TRUSTSTORE_FILE = Path.of(System.getProperty("java.io.tmpdir"), "kc-it-system-truststore.pem");

    private static final byte[] STARTUP_TRUSTED_CERTIFICATE = readResource("org/keycloak/tests/ssl/smtp-server.pem");
    private static final byte[] STARTUP_TRUSTED_KEYSTORE = readResource("org/keycloak/tests/ssl/smtp-server.p12");
    private static final String STARTUP_TRUSTED_KEYSTORE_PASSWORD = "changeit";
    private static final String FRESH_KEYSTORE_PASSWORD = "password";
    private static final AtomicInteger CA_SEQUENCE = new AtomicInteger();

    static {
        try {
            Files.write(TRUSTSTORE_FILE, STARTUP_TRUSTED_CERTIFICATE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @InjectRunOnServer(permittedPackages = "org.keycloak.tests.truststore")
    RunOnServerClient runOnServer;

    private Vertx vertx;

    @BeforeEach
    void resetSystemTruststore() throws IOException {
        vertx = Vertx.vertx();
        Files.write(TRUSTSTORE_FILE, STARTUP_TRUSTED_CERTIFICATE);
        triggerReload();
    }

    @AfterEach
    void closeVertx() throws Exception {
        vertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }

    @Test
    void outboundHttpClientPicksUpRotatedCaAfterReload() throws Exception {
        try (TlsPeer trusted = startTrustedPeer(); TlsPeer rotated = startPeerWithFreshCa()) {
            assertTrue(httpClientTrusts(url(trusted)), "startup-trusted peer must be trusted");
            assertFalse(httpClientTrusts(url(rotated)), "fresh peer must not be trusted before reload");

            rotateSystemTruststoreTo(rotated.certificateAuthority);
            triggerReload();

            awaitTrusted(() -> httpClientTrusts(url(rotated)));
        }
    }

    @Test
    void ldapsSocketFactoryPicksUpRotatedCaAfterReload() throws Exception {
        try (TlsPeer trusted = startTrustedPeer(); TlsPeer rotated = startPeerWithFreshCa()) {
            assertTrue(ldapsSocketFactoryTrusts(trusted.port()), "startup-trusted peer must be trusted");
            assertFalse(ldapsSocketFactoryTrusts(rotated.port()), "fresh peer must not be trusted before reload");

            rotateSystemTruststoreTo(rotated.certificateAuthority);
            triggerReload();

            awaitTrusted(() -> ldapsSocketFactoryTrusts(rotated.port()));
        }
    }

    @Test
    void nginxLookupPicksUpRotatedCaAfterReload() throws Exception {
        X509Certificate rotatedCa = generateCertificateAuthority();
        String rotatedSubject = rotatedCa.getSubjectX500Principal().getName();

        assertTrue(nginxLookupTrusts(startupTrustedSubject()), "startup-trusted ca must be trusted");
        assertFalse(nginxLookupTrusts(rotatedSubject), "fresh ca must not be trusted before reload");

        rotateSystemTruststoreTo(rotatedCa);
        triggerReload();

        awaitTrusted(() -> nginxLookupTrusts(rotatedSubject));
    }

    private boolean httpClientTrusts(String url) {
        return runOnServer.fetch(session -> {
            try {
                return "ok".equals(session.getProvider(HttpClientProvider.class).getString(url));
            } catch (Exception untrusted) {
                return Boolean.FALSE;
            }
        }, Boolean.class);
    }

    private boolean ldapsSocketFactoryTrusts(int port) {
        return runOnServer.fetch(session -> {
            try {
                javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) org.keycloak.truststore.SSLSocketFactory
                        .getDefault().createSocket("localhost", port);
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
                java.util.Set<String> subjects = new java.util.HashSet<>();
                for (String fieldName : new String[] { "trustedRootCerts", "intermediateCerts" }) {
                    java.lang.reflect.Field field = factory.getClass().getDeclaredField(fieldName);
                    field.setAccessible(true);
                    for (Object certificate : (java.util.Set<?>) field.get(factory)) {
                        subjects.add(((X509Certificate) certificate).getSubjectX500Principal().getName());
                    }
                }
                return subjects.contains(subject);
            } catch (Exception e) {
                return Boolean.FALSE;
            }
        }, Boolean.class);
    }

    private void triggerReload() {
        runOnServer.run(session -> SystemTruststoreReload.reload(session));
    }

    private void awaitTrusted(Callable<Boolean> trusted) {
        Awaitility.await().atMost(Duration.ofSeconds(20)).pollInterval(Duration.ofMillis(500)).until(trusted);
    }

    private static void rotateSystemTruststoreTo(X509Certificate certificateAuthority) throws IOException {
        Files.writeString(TRUSTSTORE_FILE, certificatePem(certificateAuthority));
    }

    private static String url(TlsPeer peer) {
        return "https://localhost:" + peer.port() + "/";
    }

    private TlsPeer startTrustedPeer() throws Exception {
        HttpServer server = startHttpsPeer(new PfxOptions()
                .setValue(Buffer.buffer(STARTUP_TRUSTED_KEYSTORE))
                .setPassword(STARTUP_TRUSTED_KEYSTORE_PASSWORD));
        return new TlsPeer(server, null);
    }

    private TlsPeer startPeerWithFreshCa() throws Exception {
        KeyPair caKeyPair = generateKeyPair();
        X509Certificate certificateAuthority = selfSignedCertificate(caKeyPair);
        KeyPair serverKeyPair = generateKeyPair();
        X509Certificate serverCertificate = CryptoIntegration.getProvider().getCertificateUtils()
                .generateV3Certificate(serverKeyPair, caKeyPair.getPrivate(), certificateAuthority, "localhost");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", serverKeyPair.getPrivate(), FRESH_KEYSTORE_PASSWORD.toCharArray(),
                new Certificate[] { serverCertificate, certificateAuthority });
        ByteArrayOutputStream keyStoreBytes = new ByteArrayOutputStream();
        keyStore.store(keyStoreBytes, FRESH_KEYSTORE_PASSWORD.toCharArray());
        HttpServer server = startHttpsPeer(new PfxOptions()
                .setValue(Buffer.buffer(keyStoreBytes.toByteArray()))
                .setPassword(FRESH_KEYSTORE_PASSWORD));
        return new TlsPeer(server, certificateAuthority);
    }

    private HttpServer startHttpsPeer(KeyCertOptions keyCertOptions) throws Exception {
        HttpServer server = vertx
                .createHttpServer(new HttpServerOptions().setSsl(true).setKeyCertOptions(keyCertOptions))
                .requestHandler(request -> request.response().end("ok"));
        return server.listen(0, "localhost").toCompletionStage().toCompletableFuture().get(30, TimeUnit.SECONDS);
    }

    private static X509Certificate generateCertificateAuthority() throws Exception {
        return selfSignedCertificate(generateKeyPair());
    }

    private static String startupTrustedSubject() {
        return PemUtils.decodeCertificate(new String(STARTUP_TRUSTED_CERTIFICATE, StandardCharsets.UTF_8))
                .getSubjectX500Principal().getName();
    }

    private static X509Certificate selfSignedCertificate(KeyPair caKeyPair) {
        return CryptoIntegration.getProvider().getCertificateUtils()
                .generateV1SelfSignedCertificate(caKeyPair, "Truststore Reload IT CA " + CA_SEQUENCE.incrementAndGet());
    }

    private static String certificatePem(X509Certificate certificate) {
        return PemUtils.addCertificateBeginEnd(PemUtils.encodeCertificate(certificate)) + "\n";
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

        private final HttpServer server;
        private final X509Certificate certificateAuthority;

        private TlsPeer(HttpServer server, X509Certificate certificateAuthority) {
            this.server = server;
            this.certificateAuthority = certificateAuthority;
        }

        private int port() {
            return server.actualPort();
        }

        @Override
        public void close() throws Exception {
            server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
        }
    }
}
