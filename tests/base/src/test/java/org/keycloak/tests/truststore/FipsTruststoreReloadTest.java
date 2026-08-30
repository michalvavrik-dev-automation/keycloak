package org.keycloak.tests.truststore;

import org.keycloak.common.Profile;
import org.keycloak.config.TruststoreOptions;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

@KeycloakIntegrationTest(config = FipsTruststoreReloadTest.ServerConfig.class)
class FipsTruststoreReloadTest extends AbstractTruststoreReloadTest {

    static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config
                    .features(Profile.Feature.FIPS)
                    .option("fips-mode", "non-strict")
                    .dependency("org.bouncycastle", "bc-fips")
                    .dependency("org.bouncycastle", "bctls-fips")
                    .dependency("org.bouncycastle", "bcpkix-fips")
                    .dependency("org.bouncycastle", "bcutil-fips")
                    .option(TruststoreOptions.TRUSTSTORE_PATHS.getKey(), TRUSTSTORE_FILE.toString())
                    .option(TruststoreOptions.HOSTNAME_VERIFICATION_POLICY.getKey(), "ANY");
        }
    }
}
