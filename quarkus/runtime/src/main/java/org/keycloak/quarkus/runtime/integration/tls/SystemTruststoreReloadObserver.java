package org.keycloak.quarkus.runtime.integration.tls;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.truststore.SystemTruststoreReload;
import org.keycloak.truststore.TruststoreBuilder;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.tls.CertificateUpdatedEvent;

@ApplicationScoped
public class SystemTruststoreReloadObserver {

    private static final Logger LOGGER = Logger.getLogger(SystemTruststoreReloadObserver.class);

    // Diagnostic (#51680): logs, once at startup, whether the reload wiring is in place - i.e. whether the
    // mapped reload-period reached the provider-backed TLS bucket and whether the system truststore was built.
    // If reload-period is absent here, the TLS registry never starts a timer, so no CertificateUpdatedEvent is
    // ever fired and the reload chain is inert regardless of the observer/re-merge code below.
    void onStartup(@Observes StartupEvent event) {
        String bucketReloadPeriod = ConfigProvider.getConfig()
                .getOptionalValue("quarkus.tls.\"" + SystemTruststoreReload.TLS_BUCKET_PREFIX + "\".reload-period", String.class)
                .orElse("<absent>");
        String kcReloadPeriod = ConfigProvider.getConfig()
                .getOptionalValue("kc.truststore-paths-reload-period", String.class).orElse("<absent>");
        LOGGER.infof("[truststore-reload] startup: kc.truststore-paths-reload-period=%s, mapped %s.reload-period=%s, systemTruststoreBuilt=%s",
                kcReloadPeriod, SystemTruststoreReload.TLS_BUCKET_PREFIX, bucketReloadPeriod,
                TruststoreBuilder.getSystemTruststore() != null);
    }

    void onSystemTruststoreUpdated(@Observes CertificateUpdatedEvent event) {
        // Diagnostic (#51680): if this never logs, the timer/CertificateUpdatedEvent hop is the break (timer not
        // started, or VertxCertificateHolder.reload() returning false because the bucket has a null trustStore).
        LOGGER.infof("[truststore-reload] observer received CertificateUpdatedEvent name=%s", event.name());
        if (!event.name().startsWith(SystemTruststoreReload.TLS_BUCKET_PREFIX)) {
            return;
        }
        DefaultKeycloakSessionFactory sessionFactory = KeycloakApplication.getSessionFactory();
        if (sessionFactory != null) {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, SystemTruststoreReload::reload);
        } else {
            LOGGER.warn("[truststore-reload] observer fired but KeycloakApplication.getSessionFactory() is null; skipping reload");
        }
    }
}
