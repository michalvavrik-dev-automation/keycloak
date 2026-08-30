package org.keycloak.truststore;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.keycloak.common.Profile;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSession;
import org.keycloak.services.resteasy.ResteasyKeycloakSessionFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class SystemTruststoreReloadTest {

    private CryptoProvider originalCryptoProvider;
    private ResteasyKeycloakSessionFactory sessionFactory;

    @Before
    public void setUp() {
        originalCryptoProvider = CryptoIntegration.isInitialised() ? CryptoIntegration.getProvider() : null;
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
        Profile.defaults();
    }

    @After
    public void tearDown() {
        if (sessionFactory != null) {
            sessionFactory.close();
        }
        CryptoIntegration.setProvider(originalCryptoProvider);
    }

    @Test
    public void perCallConsumersSeeRotatedTruststoreAfterReload() throws Exception {
        X509Certificate caA = selfSignedCa("Test CA A");
        X509Certificate caB = selfSignedCa("Test CA B");

        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
        KeycloakSession session = new ResteasyKeycloakSession(sessionFactory);
        fileTruststoreProviderFactory().setProvider(providerTrusting(caA));

        assertNotNull("CA A present before reload", currentTruststore(session).getCertificateAlias(caA));
        assertNull("CA B absent before reload", currentTruststore(session).getCertificateAlias(caB));

        SystemTruststoreReload.propagate(providerTrusting(caB));

        assertNotNull("CA B present after reload", currentTruststore(session).getCertificateAlias(caB));
    }

    private static KeyStore currentTruststore(KeycloakSession session) {
        return session.getProvider(TruststoreProvider.class).getTruststore();
    }

    private FileTruststoreProviderFactory fileTruststoreProviderFactory() {
        return (FileTruststoreProviderFactory) sessionFactory.getProviderFactory(TruststoreProvider.class, "file");
    }

    private static X509Certificate selfSignedCa(String commonName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return CryptoIntegration.getProvider().getCertificateUtils()
                .generateV1SelfSignedCertificate(generator.generateKeyPair(), commonName);
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
}
