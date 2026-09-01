package org.keycloak.quarkus.runtime.integration.tls;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.truststore.SystemTruststoreReload;

import io.quarkus.tls.CertificateUpdatedEvent;
import org.jboss.logging.Logger;

@ApplicationScoped
public class SystemTruststoreReloadObserver {

    private static final Logger LOGGER = Logger.getLogger(SystemTruststoreReloadObserver.class);

    void onSystemTruststoreUpdated(@Observes CertificateUpdatedEvent event) {
        if (!SystemTruststoreReload.TLS_BUCKET_PREFIX.equalsIgnoreCase(event.name())) {
            return;
        }
        if (!SystemTruststoreReload.hasPendingConsumerNotification()) {
            // The provider's getTrustStore already re-merged (or detected no change) for this reload period,
            // so there is nothing new to propagate. Skip early to avoid opening a transaction on no-op periods.
            return;
        }
        DefaultKeycloakSessionFactory sessionFactory = KeycloakApplication.getSessionFactory();
        if (sessionFactory != null) {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, SystemTruststoreReload::notifyConsumers);
        } else {
            LOGGER.warn("System truststore was reloaded but the session factory is not available yet; skipping consumer refresh");
        }
    }
}
