package org.keycloak.tests.admin.client.v2;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.keycloak.common.Profile;
import org.keycloak.testframework.annotations.InjectHttpClient;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * TEMPORARY: runs a few filters with Hibernate SQL logging enabled on the server so the generated SQL can be
 * inspected in the test log (run with KC_TEST_LOG_CATEGORY__MANAGED_KEYCLOAK__LEVEL=DEBUG). Not for any PR.
 */
@KeycloakIntegrationTest(config = NullSemanticsSqlLogTest.Config.class)
public class NullSemanticsSqlLogTest extends AbstractClientApiV2Test {

    @InjectHttpClient
    CloseableHttpClient httpClient;

    @InjectRealm
    ManagedRealm testRealm;

    @Override
    public String getRealmName() {
        return testRealm.getName();
    }

    public static class Config implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.CLIENT_ADMIN_API_V2)
                    .option("log-level", "info,org.hibernate.SQL:debug,org.hibernate.orm.jdbc.bind:trace");
        }
    }

    @Test
    public void logSql() throws IOException {
        for (String q : List.of(
                "description eq null",
                "description ne null",
                "not (description eq null)",
                "description ne \"x\"",
                "not (description eq \"x\")",
                "description pr",
                "not description pr",
                "auth.method eq null",
                "roles ne \"admin\"",
                "not (roles eq \"admin\")")) {
            System.out.println("[NULLSEM-SQL] >>> q=" + q);
            HttpGet request = new HttpGet(getClientsApiUrl() + "?q=" + URLEncoder.encode(q, StandardCharsets.UTF_8));
            setAuthHeader(request);
            try (var response = httpClient.execute(request)) {
                String body = EntityUtils.toString(response.getEntity());
                assertThat(q + " -> " + body, response.getStatusLine().getStatusCode(), is(200));
            }
            System.out.println("[NULLSEM-SQL] <<< q=" + q);
        }
    }
}
