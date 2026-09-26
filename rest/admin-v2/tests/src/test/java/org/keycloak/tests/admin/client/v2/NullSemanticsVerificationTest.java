package org.keycloak.tests.admin.client.v2;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.keycloak.representations.admin.v2.BaseClientRepresentation;
import org.keycloak.representations.admin.v2.OIDCClientRepresentation;
import org.keycloak.representations.admin.v2.SAMLClientRepresentation;
import org.keycloak.testframework.annotations.InjectHttpClient;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedRealm;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * TEMPORARY verification of SQL three-valued null semantics in Admin API v2 client filtering.
 * Not intended to be part of any PR. Every query prints a "[NULLSEM]" line with the raw outcome.
 */
@KeycloakIntegrationTest(config = ClientQueryTest.Config.class)
public class NullSemanticsVerificationTest extends AbstractClientApiV2Test {

    // OIDC, has description, confidential (client-secret), roles admin + viewer
    private static final String OIDC_DESC = "nulltest-oidc-desc";
    // OIDC, no description, public (auth == null), no roles
    private static final String OIDC_NODESC = "nulltest-oidc-nodesc";
    // SAML, no description, no roles
    private static final String SAML_NODESC = "nulltest-saml-nodesc";
    // SAML, has description, role viewer
    private static final String SAML_DESC = "nulltest-saml-desc";

    private static final String DESCRIPTION = "has description";

    @InjectHttpClient
    CloseableHttpClient httpClient;

    @InjectRealm
    ManagedRealm testRealm;

    @Override
    public String getRealmName() {
        return testRealm.getName();
    }

    @BeforeEach
    public void setupClients() {
        var clients = getClientsApi();

        var oidcDesc = new OIDCClientRepresentation(OIDC_DESC);
        oidcDesc.setEnabled(true);
        oidcDesc.setDescription(DESCRIPTION);
        var auth = new OIDCClientRepresentation.Auth();
        auth.setMethod("client-secret");
        oidcDesc.setAuth(auth);
        oidcDesc.setRoles(Set.of("admin", "viewer"));
        try (var response = clients.createClient(oidcDesc)) {
            assertThat(response.getStatus(), is(201));
            var created = response.readEntity(OIDCClientRepresentation.class);
            testRealm.cleanup().add(realm -> realm.clients().delete(created.getUuid()));
        }

        var oidcNoDesc = new OIDCClientRepresentation(OIDC_NODESC);
        oidcNoDesc.setEnabled(true);
        try (var response = clients.createClient(oidcNoDesc)) {
            assertThat(response.getStatus(), is(201));
            var created = response.readEntity(OIDCClientRepresentation.class);
            testRealm.cleanup().add(realm -> realm.clients().delete(created.getUuid()));
            // sanity: without auth the client is public, so auth (and auth.method) is absent
            assertNull(created.getAuth(), "expected public client without auth");
            assertNull(created.getDescription());
        }

        var samlNoDesc = new SAMLClientRepresentation();
        samlNoDesc.setClientId(SAML_NODESC);
        samlNoDesc.setEnabled(true);
        try (var response = clients.createClient(samlNoDesc)) {
            assertThat(response.getStatus(), is(201));
            var created = response.readEntity(SAMLClientRepresentation.class);
            testRealm.cleanup().add(realm -> realm.clients().delete(created.getUuid()));
        }

        var samlDesc = new SAMLClientRepresentation();
        samlDesc.setClientId(SAML_DESC);
        samlDesc.setEnabled(true);
        samlDesc.setDescription("saml " + DESCRIPTION);
        samlDesc.setRoles(Set.of("viewer"));
        try (var response = clients.createClient(samlDesc)) {
            assertThat(response.getStatus(), is(201));
            var created = response.readEntity(SAMLClientRepresentation.class);
            testRealm.cleanup().add(realm -> realm.clients().delete(created.getUuid()));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // eq null / ne null on a nullable direct column (description)
    // ---------------------------------------------------------------------------------------------

    @Test
    public void eqNullAndNeNullNeverMatchDirectColumn() throws IOException {
        // SQL: description = NULL -> UNKNOWN for every row, including rows whose description IS NULL
        assertThat(all("description eq null"), empty());
        assertThat(all("description ne null"), empty());
        // NOT UNKNOWN is still UNKNOWN
        assertThat(all("not (description eq null)"), empty());
        assertThat(all("not (description ne null)"), empty());
        // case-insensitive literal spelling
        assertThat(all("description eq NULL"), empty());
    }

    @Test
    public void presenceIsTheWayToTestForNull() throws IOException {
        assertThat(ids("description pr"), containsInAnyOrder(OIDC_DESC, SAML_DESC));
        assertThat(ids("not description pr"), containsInAnyOrder(OIDC_NODESC, SAML_NODESC));
        assertThat(ids("not (description pr)"), containsInAnyOrder(OIDC_NODESC, SAML_NODESC));
    }

    @Test
    public void neAndNegatedEqExcludeNullRows() throws IOException {
        // SQL: description <> 'has description' -> UNKNOWN when description IS NULL -> row excluded
        assertThat(ids("description ne \"" + DESCRIPTION + "\""), containsInAnyOrder(SAML_DESC));
        // NOT (description = 'has description') -> also UNKNOWN for NULL rows
        assertThat(ids("not (description eq \"" + DESCRIPTION + "\")"), containsInAnyOrder(SAML_DESC));
        assertThat(ids("not (description co \"has\")"), empty());
        assertThat(ids("not (description sw \"has\")"), containsInAnyOrder(SAML_DESC));
        assertThat(ids("not (description ew \"description\")"), empty());
    }

    @Test
    public void unknownCombinesLikeSql() throws IOException {
        // UNKNOWN OR TRUE = TRUE ; UNKNOWN OR FALSE = UNKNOWN
        assertThat(ids("description eq null or description pr"), containsInAnyOrder(OIDC_DESC, SAML_DESC));
        // UNKNOWN AND TRUE = UNKNOWN
        assertThat(ids("description eq null and description pr"), empty());
        assertThat(ids("description eq null and enabled eq true"), empty());
    }

    // ---------------------------------------------------------------------------------------------
    // derived (CASE) expression: auth.method is NULL for SAML clients and for public OIDC clients
    // ---------------------------------------------------------------------------------------------

    @Test
    public void derivedFieldAuthMethod() throws IOException {
        assertThat(all("auth.method eq null"), empty());
        assertThat(all("auth.method ne null"), empty());
        assertThat(ids("auth.method pr"), containsInAnyOrder(OIDC_DESC));
        assertThat(ids("not auth.method pr"), containsInAnyOrder(OIDC_NODESC, SAML_NODESC, SAML_DESC));
        // NULL <> 'client-secret' -> UNKNOWN -> public + SAML clients are NOT returned
        assertThat(ids("auth.method ne \"client-secret\""), empty());
        assertThat(ids("not (auth.method eq \"client-secret\")"), empty());
    }

    // ---------------------------------------------------------------------------------------------
    // collection-backed attribute (roles): EXISTS subquery semantics
    // ---------------------------------------------------------------------------------------------

    @Test
    public void collectionBackedRoles() throws IOException {
        assertThat(all("roles eq null"), empty());
        assertThat(all("roles ne null"), empty());
        assertThat(ids("roles pr"), containsInAnyOrder(OIDC_DESC, SAML_DESC));
        assertThat(ids("not roles pr"), containsInAnyOrder(OIDC_NODESC, SAML_NODESC));
        // EXISTS(role.name <> 'admin'): clients with at least one other role; clients with NO roles are excluded
        assertThat(ids("roles ne \"admin\""), containsInAnyOrder(OIDC_DESC, SAML_DESC));
        // NOT EXISTS(role.name = 'admin'): clients with no 'admin' role, including clients with no roles at all
        assertThat(ids("not (roles eq \"admin\")"), containsInAnyOrder(OIDC_NODESC, SAML_NODESC, SAML_DESC));
        // a client whose only role is 'viewer' does not satisfy ne 'viewer'
        assertThat(ids("roles ne \"viewer\""), containsInAnyOrder(OIDC_DESC));
    }

    // ---------------------------------------------------------------------------------------------
    // boolean, timestamp, non-null string columns
    // ---------------------------------------------------------------------------------------------

    @Test
    public void nullOnBooleanTimestampAndNonNullColumns() throws IOException {
        assertThat(all("enabled eq null"), empty());
        assertThat(all("enabled ne null"), empty());
        assertThat(ids("enabled pr"), containsInAnyOrder(OIDC_DESC, OIDC_NODESC, SAML_NODESC, SAML_DESC));
        assertThat(all("createdTimestamp eq null"), empty());
        assertThat(all("createdTimestamp ne null"), empty());
        assertThat(ids("createdTimestamp pr"), containsInAnyOrder(OIDC_DESC, OIDC_NODESC, SAML_NODESC, SAML_DESC));
        assertThat(all("clientId eq null"), empty());
        assertThat(all("protocol eq null"), empty());
        assertThat(all("displayName eq null"), empty());
        assertThat(all("appUrl eq null"), empty());
    }

    // ---------------------------------------------------------------------------------------------
    // null with any operator other than eq/ne is rejected at parse time
    // ---------------------------------------------------------------------------------------------

    @Test
    public void nullWithOtherOperatorsIsRejected() throws IOException {
        for (String q : List.of("description co null", "description sw null", "description ew null",
                "createdTimestamp gt null", "createdTimestamp ge null", "createdTimestamp lt null", "createdTimestamp le null")) {
            Result r = query(q);
            System.out.println("[NULLSEM] q=" + q + " -> status " + r.status() + " body=" + r.body());
            assertThat(q, r.status(), is(400));
            assertThat(q, r.body().contains("does not accept null values"), is(true));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // side check: which fields listed in querying.adoc are actually searchable
    // ---------------------------------------------------------------------------------------------

    @Test
    public void searchabilityOfDocumentedFields() throws IOException {
        for (String q : List.of("redirectUris eq \"http://localhost/callback\"", "redirectUris pr", "webOrigins pr",
                "loginFlows eq \"STANDARD\"", "serviceAccountRoles pr", "signDocuments eq true", "nameIdFormat pr",
                "uuid pr", "auth pr", "appUrl pr", "displayName pr", "updatedTimestamp pr", "roles pr")) {
            Result r = query(q);
            System.out.println("[NULLSEM] searchable? q=" + q + " -> status " + r.status()
                    + (r.status() != 200 ? " body=" + r.body() : ""));
        }
    }

    // ---------------------------------------------------------------------------------------------

    private record Result(int status, List<BaseClientRepresentation> clients, String body) {}

    private Result query(String q) throws IOException {
        HttpGet request = new HttpGet(getClientsApiUrl() + "?q=" + URLEncoder.encode(q, StandardCharsets.UTF_8));
        setAuthHeader(request);
        try (var response = httpClient.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            String body = EntityUtils.toString(response.getEntity());
            if (status != 200) {
                return new Result(status, List.of(), body);
            }
            return new Result(status, mapper.readValue(body, new TypeReference<>() {}), body);
        }
    }

    /** clientIds of the test clients (prefix nulltest-) returned for the query; asserts HTTP 200 */
    private Set<String> ids(String q) throws IOException {
        Set<String> all = all(q);
        Set<String> mine = all.stream().filter(id -> id.startsWith("nulltest-")).collect(Collectors.toCollection(TreeSet::new));
        System.out.println("[NULLSEM] q=" + q + " -> test clients " + mine);
        return mine;
    }

    /** all clientIds returned for the query; asserts HTTP 200 */
    private Set<String> all(String q) throws IOException {
        Result r = query(q);
        assertThat(q + " -> " + r.body(), r.status(), is(200));
        Set<String> all = r.clients().stream().map(BaseClientRepresentation::getClientId).collect(Collectors.toCollection(TreeSet::new));
        System.out.println("[NULLSEM] q=" + q + " -> all clients " + all);
        return all;
    }
}
