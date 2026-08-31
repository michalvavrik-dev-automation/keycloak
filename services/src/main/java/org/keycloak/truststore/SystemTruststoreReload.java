package org.keycloak.truststore;

import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.JsonLdContextDocumentLoader;
import org.keycloak.provider.Provider;
import org.keycloak.services.x509.X509ClientCertificateLookup;

public final class SystemTruststoreReload {

    public static final String TLS_BUCKET_PREFIX = "keycloak-system-truststore";

    private static final Object LOCK = new Object();

    private SystemTruststoreReload() {
    }

    public static void reload(KeycloakSession session) {
        synchronized (LOCK) {
            TruststoreBuilder.reloadSystemTruststore();
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            notifyListeners(sessionFactory, TruststoreProvider.class);
            SSLSocketFactory.reset();
            notifyListeners(sessionFactory, HttpClientProvider.class);
            notifyListeners(sessionFactory, X509ClientCertificateLookup.class);
            JsonLdContextDocumentLoader.reset();
        }
    }

    private static void notifyListeners(KeycloakSessionFactory sessionFactory, Class<? extends Provider> providerClass) {
        sessionFactory.getProviderFactoriesStream(providerClass)
                .filter(TruststoreReloadListener.class::isInstance)
                .map(TruststoreReloadListener.class::cast)
                .forEach(TruststoreReloadListener::truststoreReloaded);
    }
}
