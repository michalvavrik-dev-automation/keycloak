/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.truststore;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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

/**
 * Reload test for the {@code ldaps://} (non-StartTLS) path of the LDAP client, which routes trust through the static
 * {@link SSLSocketFactory} named as {@code java.naming.ldap.factory.socket} in
 * {@code LDAPContextManager} (see {@code LDAPContextManager.java:245}). JNDI obtains it via the static
 * {@link SSLSocketFactory#getDefault()}, which caches a socket factory built once from
 * {@link TruststoreProviderSingleton}.
 *
 * <p>This drives a <em>real TLS handshake</em> against a local server whose certificate we control — i.e. it tests
 * what a new LDAPS connection attempt actually trusts, not "was reset called". A CA is rotated and the system
 * truststore reloaded; the next handshake must trust the new CA.
 *
 * <p>RED PHASE: fails at the post-reload assertion because {@link SSLSocketFactory#reset()} is currently a no-op, so
 * {@code getDefault()} keeps returning the stale factory built from the old truststore — "configured correctly,
 * worked before reload, certificate not reloaded". It is NOT a "does not exist" failure: the initial trust decision
 * succeeds, and the sanity checks pass.
 */
public class SSLSocketFactoryReloadTest {

    private static final char[] PASSWORD = "password".toCharArray();

    private CryptoProvider originalCryptoProvider;

    @Before
    public void before() throws Exception {
        originalCryptoProvider = CryptoIntegration.isInitialised() ? CryptoIntegration.getProvider() : null;
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
        clearStaticInstance(); // test hygiene: start from a clean static singleton (reset() is a no-op in the red phase)
    }

    @After
    public void after() throws Exception {
        clearStaticInstance();
        TruststoreProviderSingleton.set(null);
        CryptoIntegration.setProvider(originalCryptoProvider);
    }

    @Test
    public void ldapsPicksUpRotatedCaAfterReload() throws Exception {
        // Two independent CAs, each signing a localhost server certificate.
        KeyPair caKeyA = generateKeyPair();
        X509Certificate caCertA = generateCa(caKeyA, "Test CA A");
        KeyPair caKeyB = generateKeyPair();
        X509Certificate caCertB = generateCa(caKeyB, "Test CA B");

        try (TestTlsServer serverA = new TestTlsServer(serverKeyStore(caKeyA, caCertA));
             TestTlsServer serverB = new TestTlsServer(serverKeyStore(caKeyB, caCertB))) {

            // The system truststore initially trusts CA A only.
            TruststoreProviderSingleton.set(providerTrusting(caCertA));

            // Everything works before reload: an LDAPS-style connection to the A-signed server is trusted...
            assertTrue("A-signed server should be trusted before reload", handshakeSucceeds(serverA.port));
            // ...and the not-yet-trusted CA B is correctly rejected.
            assertFalse("B-signed server should not be trusted before reload", handshakeSucceeds(serverB.port));

            // Rotate the system truststore to CA B and reload.
            TruststoreProviderSingleton.set(providerTrusting(caCertB));
            SSLSocketFactory.reset();

            // A new LDAPS connection attempt must now trust the rotated CA B.
            assertTrue("B-signed server should be trusted after reload", handshakeSucceeds(serverB.port));
        }
    }

    // --- helpers -----------------------------------------------------------------------------------------------------

    private static boolean handshakeSucceeds(int port) throws IOException {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault()
                .createSocket(InetAddress.getLoopbackAddress().getHostAddress(), port)) {
            // isolate the test to trust decisions; hostname verification is a separate concern (tls-hostname-verifier)
            SSLParameters params = socket.getSSLParameters();
            params.setEndpointIdentificationAlgorithm(null);
            socket.setSSLParameters(params);
            socket.startHandshake();
            return true;
        } catch (SSLException e) {
            return false;
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static X509Certificate generateCa(KeyPair caKeyPair, String cn) {
        return CryptoIntegration.getProvider().getCertificateUtils().generateV1SelfSignedCertificate(caKeyPair, cn);
    }

    private static KeyStore serverKeyStore(KeyPair caKeyPair, X509Certificate caCert) throws Exception {
        KeyPair serverKeyPair = generateKeyPair();
        X509Certificate serverCert = CryptoIntegration.getProvider().getCertificateUtils()
                .generateV3Certificate(serverKeyPair, caKeyPair.getPrivate(), caCert, "localhost");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", serverKeyPair.getPrivate(), PASSWORD,
                new Certificate[] { serverCert, caCert });
        return keyStore;
    }

    private static TruststoreProvider providerTrusting(X509Certificate ca) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        return new TestTruststoreProvider(trustStore);
    }

    private static void clearStaticInstance() throws Exception {
        Field instance = SSLSocketFactory.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /** Minimal {@link TruststoreProvider} that only supplies a truststore (all {@code getDefault()} needs). */
    private static final class TestTruststoreProvider implements TruststoreProvider {
        private final KeyStore truststore;

        TestTruststoreProvider(KeyStore truststore) {
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
        public Map<X500Principal, java.util.List<X509Certificate>> getRootCertificates() {
            return Map.of();
        }

        @Override
        public Map<X500Principal, java.util.List<X509Certificate>> getIntermediateCertificates() {
            return Map.of();
        }

        @Override
        public KeyStore getHttpsTruststore() {
            return truststore;
        }

        @Override
        public Map<X500Principal, java.util.List<X509Certificate>> getHttpsRootCertificates() {
            return Map.of();
        }

        @Override
        public Map<X500Principal, java.util.List<X509Certificate>> getHttpsIntermediateCertificates() {
            return Map.of();
        }

        @Override
        public void close() {
        }
    }

    /** A local TLS server presenting the supplied key material; accepts and completes handshakes until closed. */
    private static final class TestTlsServer implements AutoCloseable {
        private final SSLServerSocket serverSocket;
        private final Thread thread;
        final int port;
        private volatile boolean running = true;

        TestTlsServer(KeyStore keyStore) throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, PASSWORD);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            serverSocket = (SSLServerSocket) context.getServerSocketFactory()
                    .createServerSocket(0, 0, InetAddress.getLoopbackAddress());
            port = serverSocket.getLocalPort();
            thread = new Thread(this::acceptLoop, "test-tls-server-" + port);
            thread.setDaemon(true);
            thread.start();
        }

        private void acceptLoop() {
            while (running) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.startHandshake();
                    socket.getInputStream().read();
                } catch (Exception ignored) {
                    // untrusted client handshake or server shutting down
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
