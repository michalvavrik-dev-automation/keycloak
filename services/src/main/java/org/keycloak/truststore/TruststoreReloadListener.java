package org.keycloak.truststore;

import org.keycloak.models.KeycloakSession;

public interface TruststoreReloadListener {

    void truststoreReloaded(KeycloakSession session);
}
