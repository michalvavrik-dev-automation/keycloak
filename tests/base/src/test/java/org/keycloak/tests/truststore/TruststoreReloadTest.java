package org.keycloak.tests.truststore;

import org.keycloak.config.TruststoreOptions;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

@KeycloakIntegrationTest(config = TruststoreReloadTest.ServerConfig.class)
class TruststoreReloadTest extends AbstractTruststoreReloadTest {

    static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config
                    .option(TruststoreOptions.TRUSTSTORE_PATHS.getKey(), TRUSTSTORE_FILE.toString())
                    .option(TruststoreOptions.HOSTNAME_VERIFICATION_POLICY.getKey(), "ANY");
        }
    }
}
