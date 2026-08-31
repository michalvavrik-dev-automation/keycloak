package org.keycloak.quarkus.runtime.integration.tls;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.truststore.SystemTruststoreReload;

import io.quarkus.tls.CertificateUpdatedEvent;

@ApplicationScoped
public class SystemTruststoreReloadObserver {

    void onSystemTruststoreUpdated(@Observes CertificateUpdatedEvent event) {
        if (!event.name().startsWith(SystemTruststoreReload.TLS_BUCKET_PREFIX)) {
            return;
        }
        DefaultKeycloakSessionFactory sessionFactory = KeycloakApplication.getSessionFactory();
        if (sessionFactory != null) {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, SystemTruststoreReload::reload);
        }
    }
}
