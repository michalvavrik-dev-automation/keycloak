package org.keycloak.truststore;

import java.util.concurrent.atomic.AtomicLong;

import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.JsonLdContextDocumentLoader;
import org.keycloak.provider.Provider;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import org.jboss.logging.Logger;

public final class SystemTruststoreReload {

    public static final String TLS_BUCKET_PREFIX = "keycloak-system-truststore";

    private static final Logger LOGGER = Logger.getLogger(SystemTruststoreReload.class);

    private static final Object LOCK = new Object();

    private static final AtomicLong RELOAD_COUNT = new AtomicLong();

    // Highest RELOAD_COUNT value that the legacy (non-registry) consumers have already been notified about.
    private static final AtomicLong NOTIFIED_COUNT = new AtomicLong();

    private SystemTruststoreReload() {
    }

    // Number of times a reload actually re-merged the truststore (skipped no-op intervals are not counted).
    public static long reloadCount() {
        return RELOAD_COUNT.get();
    }

    /**
     * Re-merge the system truststore if any source changed since the last merge, returning whether a re-merge
     * happened. Invoked from {@code SystemTruststoreProvider.getTrustStore} so the provider-backed TLS-registry
     * bucket serves the freshly merged store within the SAME reload tick (no one-period lag), and defensively
     * from {@link #notifyConsumers}. Thread-safe; the underlying fingerprint check no-ops on unchanged sources,
     * so this is cheap to call every reload period and only advances {@link #reloadCount()} on a real change.
     */
    public static boolean reloadIfChanged() {
        synchronized (LOCK) {
            if (!TruststoreBuilder.reloadSystemTruststoreIfChanged()) {
                LOGGER.debug("System truststore sources unchanged; nothing to reload");
                return false;
            }
            long count = RELOAD_COUNT.incrementAndGet();
            LOGGER.infof("System truststore re-merged (reloadCount=%d)", count);
            return true;
        }
    }

    /**
     * True if a re-merge has happened that the legacy consumers have not yet been refreshed for. Lets the reload
     * observer skip opening a DB transaction on the (common) no-op reload periods (#51680).
     */
    public static boolean hasPendingConsumerNotification() {
        return RELOAD_COUNT.get() != NOTIFIED_COUNT.get();
    }

    /**
     * Refresh the legacy (non-registry) truststore consumers - the shared Apache HttpClient, the nginx mTLS
     * lookup, the LDAP {@link SSLSocketFactory}, the JSON-LD document loader and the file
     * {@link TruststoreProvider} - after a re-merge. The registry bucket refreshes itself via
     * {@link #reloadIfChanged}. No-op when nothing changed since the last notification, so it is safe to invoke
     * on every reload tick. Consumers are refreshed in dependency order: the {@link TruststoreProvider} first,
     * then the components that read through it.
     */
    public static void notifyConsumers(KeycloakSession session) {
        synchronized (LOCK) {
            // Ensure the latest merge has landed even if getTrustStore has not run this tick (defensive; a
            // no-op when the provider already re-merged, so it never double-counts a change).
            reloadIfChanged();
            long count = RELOAD_COUNT.get();
            if (count == NOTIFIED_COUNT.get()) {
                LOGGER.debugf("System truststore consumers already refreshed for reloadCount=%d; skipping", count);
                return;
            }
            NOTIFIED_COUNT.set(count);
            LOGGER.infof("Refreshing system truststore consumers after reload (reloadCount=%d)", count);
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
