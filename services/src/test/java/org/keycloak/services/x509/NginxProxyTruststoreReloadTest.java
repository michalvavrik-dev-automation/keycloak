package org.keycloak.services.x509;

import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.keycloak.utils.ScopeUtil;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NginxProxyTruststoreReloadTest {

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
    public void nginxLookupPicksUpRotatedRootCaAfterReload() throws Exception {
        X509Certificate rootCaA = selfSignedCa("Root CA A");
        X509Certificate rootCaB = selfSignedCa("Root CA B");

        sessionFactory = new ResteasyKeycloakSessionFactory();
        sessionFactory.init();
        KeycloakSession session = new ResteasyKeycloakSession(sessionFactory);
        fileTruststoreProviderFactory().setProvider(providerWithRootCertificate(rootCaA));

        NginxProxySslClientCertificateLookupFactory lookupFactory = new NginxProxySslClientCertificateLookupFactory();
        lookupFactory.init(ScopeUtil.createScope(new HashMap<>()));

        lookupFactory.create(session);
        assertTrue("root CA A should be trusted before reload", trustedRootCertificates(lookupFactory).contains(rootCaA));
        assertFalse("root CA B should not be trusted before reload", trustedRootCertificates(lookupFactory).contains(rootCaB));

        SystemTruststoreReload.propagate(providerWithRootCertificate(rootCaB));

        lookupFactory.create(session);
        assertTrue("root CA B should be trusted after reload", trustedRootCertificates(lookupFactory).contains(rootCaB));
    }

    @SuppressWarnings("unchecked")
    private static Set<X509Certificate> trustedRootCertificates(NginxProxySslClientCertificateLookupFactory factory)
            throws Exception {
        Field field = NginxProxySslClientCertificateLookupFactory.class.getDeclaredField("trustedRootCerts");
        field.setAccessible(true);
        return (Set<X509Certificate>) field.get(factory);
    }

    private FileTruststoreProviderFactory fileTruststoreProviderFactory() {
        return (FileTruststoreProviderFactory) sessionFactory.getProviderFactory(TruststoreProvider.class, "file");
    }

    private static X509Certificate selfSignedCa(String commonName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return CryptoIntegration.getProvider().getCertificateUtils().generateV1SelfSignedCertificate(keyPair, commonName);
    }

    private static TruststoreProvider providerWithRootCertificate(X509Certificate ca) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        Map<X500Principal, List<X509Certificate>> roots = Map.of(ca.getSubjectX500Principal(), List.of(ca));
        return new RootCertificateTruststoreProvider(trustStore, roots);
    }

    private static final class RootCertificateTruststoreProvider implements TruststoreProvider {

        private final KeyStore truststore;
        private final Map<X500Principal, List<X509Certificate>> roots;

        private RootCertificateTruststoreProvider(KeyStore truststore, Map<X500Principal, List<X509Certificate>> roots) {
            this.truststore = truststore;
            this.roots = roots;
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
            return roots;
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
            return roots;
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
