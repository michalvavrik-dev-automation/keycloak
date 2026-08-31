package org.keycloak.truststore;

import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.JsonLdContextDocumentLoader;
import org.keycloak.provider.Provider;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import java.util.concurrent.atomic.AtomicLong;

public final class SystemTruststoreReload {

    public static final String TLS_BUCKET_PREFIX = "keycloak-system-truststore";

    private static final Object LOCK = new Object();

    private static final AtomicLong RELOAD_COUNT = new AtomicLong();

    private SystemTruststoreReload() {
    }

    // Number of times a reload actually re-merged the truststore (skipped no-op intervals are not counted).
    public static long reloadCount() {
        return RELOAD_COUNT.get();
    }

    public static void reload(KeycloakSession session) {
        synchronized (LOCK) {
            if (!TruststoreBuilder.reloadSystemTruststoreIfChanged()) {
                return;
            }
            RELOAD_COUNT.incrementAndGet();
            KeycloakSessionFactory sessionFactory = session.getKeycloakSessionFactory();
            notifyListeners(session, sessionFactory, TruststoreProvider.class);
            SSLSocketFactory.reset();
            notifyListeners(session, sessionFactory, HttpClientProvider.class);
            notifyListeners(session, sessionFactory, X509ClientCertificateLookup.class);
            JsonLdContextDocumentLoader.reset();
        }
    }

    private static void notifyListeners(KeycloakSession session, KeycloakSessionFactory sessionFactory, Class<? extends Provider> providerClass) {
        sessionFactory.getProviderFactoriesStream(providerClass)
                .filter(TruststoreReloadListener.class::isInstance)
                .map(TruststoreReloadListener.class::cast)
                .forEach(listener -> listener.truststoreReloaded(session));
    }
}
