package org.keycloak.tests.scim.tck;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.keycloak.models.UserModel;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.scim.client.ScimClientException;
import org.keycloak.scim.protocol.request.PatchRequest;
import org.keycloak.scim.protocol.response.ListResponse;
import org.keycloak.scim.resource.group.Group;
import org.keycloak.scim.resource.user.EnterpriseUser;
import org.keycloak.scim.resource.user.User;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.keycloak.scim.resource.Scim.ENTERPRISE_USER_SCHEMA;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * TEMPORARY verification of SQL three-valued null semantics in SCIM filtering (Users and Groups).
 * Not intended to be part of any PR. Every query prints a "[NULLSEM]" line with the raw outcome.
 */
@KeycloakIntegrationTest
public class NullSemanticsVerificationTest extends AbstractScimTest {

    private static final String PREFIX = "nulltest-";
    private static final String ALICE = PREFIX + "alice";   // givenName, familyName, email, department, member of group A
    private static final String BOB = PREFIX + "bob";       // nothing optional set at all
    private static final String CAROL = PREFIX + "carol";   // givenName only, department Sales, inactive
    private static final String ALICE_EMAIL = "alice@nulltest.org";
    private static final String GROUP_A = PREFIX + "group-a";
    private static final String GROUP_EMPTY = PREFIX + "group-empty";
    private static final String DEPARTMENT = ENTERPRISE_USER_SCHEMA + ":department";

    private final List<String> userIdsToRemove = new ArrayList<>();
    private final List<String> groupIdsToRemove = new ArrayList<>();

    private String aliceId;
    private String groupAId;
    private String groupEmptyId;

    @BeforeEach
    public void onBefore() {
        // same trimming as FilterTest: only username/firstName/lastName/email remain, none required
        UPConfig upConfig = realm.admin().users().userProfile().getConfiguration();
        upConfig.getAttribute(UserModel.FIRST_NAME).setRequired(null);
        upConfig.getAttribute(UserModel.LAST_NAME).setRequired(null);
        upConfig.getAttribute(UserModel.EMAIL).setRequired(null);
        Iterator<UPAttribute> iterator = upConfig.getAttributes().iterator();
        while (iterator.hasNext()) {
            UPAttribute attribute = iterator.next();
            if (Set.of(UserModel.USERNAME, UserModel.FIRST_NAME, UserModel.LAST_NAME, UserModel.EMAIL).contains(attribute.getName())) {
                continue;
            }
            iterator.remove();
        }
        realm.admin().users().userProfile().update(upConfig);
        addEnterpriseUserUserProfileAttributes();

        aliceId = createUser(ALICE, "Alice", "Smith", ALICE_EMAIL, true, "Engineering").getId();
        createUser(BOB, null, null, null, true, null);
        createUser(CAROL, "Carol", null, null, false, "Sales");

        groupAId = createGroup(GROUP_A);
        groupEmptyId = createGroup(GROUP_EMPTY);
        realm.admin().users().get(aliceId).joinGroup(groupAId);
    }

    @AfterEach
    public void onAfter() {
        userIdsToRemove.forEach(id -> realm.admin().users().delete(id).close());
        groupIdsToRemove.forEach(id -> realm.admin().groups().group(id).remove());
    }

    // ---------------------------------------------------------------------------------------------
    // eq null / ne null on direct columns of USER_ENTITY (first_name, email, username, enabled, timestamps)
    // ---------------------------------------------------------------------------------------------

    @Test
    public void eqNullAndNeNullNeverMatchDirectColumns() {
        assertThat(allUsers("name.givenName eq null"), empty());
        assertThat(allUsers("name.givenName ne null"), empty());
        assertThat(allUsers("not (name.givenName eq null)"), empty());
        assertThat(allUsers("not (name.givenName ne null)"), empty());
        assertThat(allUsers("name[givenName eq null]"), empty());
        assertThat(allUsers("name.familyName eq NULL"), empty());
        assertThat(allUsers("emails eq null"), empty());
        assertThat(allUsers("emails.value eq null"), empty());
        assertThat(allUsers("emails[value eq null]"), empty());
        assertThat(allUsers("userName eq null"), empty());
        assertThat(allUsers("active eq null"), empty());
        assertThat(allUsers("active ne null"), empty());
        assertThat(allUsers("meta.created eq null"), empty());
        assertThat(allUsers("meta.lastModified eq null"), empty());
        assertThat(allUsers("externalId eq null"), empty());
    }

    @Test
    public void presenceIsTheWayToTestForNull() {
        assertThat(users("name.givenName pr"), containsInAnyOrder(ALICE, CAROL));
        assertThat(users("not (name.givenName pr)"), containsInAnyOrder(BOB));
        assertThat(users("name.familyName pr"), containsInAnyOrder(ALICE));
        assertThat(users("not (name.familyName pr)"), containsInAnyOrder(BOB, CAROL));
        assertThat(users("emails pr"), containsInAnyOrder(ALICE));
        assertThat(users("emails.value pr"), containsInAnyOrder(ALICE));
        assertThat(users("not (emails pr)"), containsInAnyOrder(BOB, CAROL));
    }

    @Test
    public void neAndNegatedEqExcludeNullRows() {
        // first_name <> 'Alice' -> UNKNOWN for bob (NULL) -> excluded
        assertThat(users("name.givenName ne \"Alice\""), containsInAnyOrder(CAROL));
        assertThat(users("not (name.givenName eq \"Alice\")"), containsInAnyOrder(CAROL));
        assertThat(users("not (name.givenName co \"li\")"), containsInAnyOrder(CAROL));
        // email <> 'alice@...' -> alice equal, bob/carol NULL -> nobody
        assertThat(users("emails ne \"" + ALICE_EMAIL + "\""), empty());
        assertThat(users("not (emails eq \"" + ALICE_EMAIL + "\")"), empty());
        assertThat(users("emails.value ne \"" + ALICE_EMAIL + "\""), empty());
    }

    @Test
    public void unknownCombinesLikeSql() {
        assertThat(users("name.givenName eq null or name.givenName pr"), containsInAnyOrder(ALICE, CAROL));
        assertThat(users("name.givenName eq null and name.givenName pr"), empty());
        assertThat(users("name.givenName eq null and active eq true"), empty());
    }

    // ---------------------------------------------------------------------------------------------
    // collection-backed custom attribute (USER_ATTRIBUTE rows): EXISTS subquery semantics
    // ---------------------------------------------------------------------------------------------

    @Test
    public void collectionBackedCustomAttribute() {
        assertThat(allUsers(DEPARTMENT + " eq null"), empty());
        assertThat(allUsers(DEPARTMENT + " ne null"), empty());
        assertThat(users(DEPARTMENT + " pr"), containsInAnyOrder(ALICE, CAROL));
        assertThat(users("not (" + DEPARTMENT + " pr)"), containsInAnyOrder(BOB));
        // EXISTS(value <> 'Engineering'): only users having some other department value; bob has no row -> excluded
        assertThat(users(DEPARTMENT + " ne \"Engineering\""), containsInAnyOrder(CAROL));
        // NOT EXISTS(value = 'Engineering'): bob (no row) and carol
        assertThat(users("not (" + DEPARTMENT + " eq \"Engineering\")"), containsInAnyOrder(BOB, CAROL));
    }

    // ---------------------------------------------------------------------------------------------
    // relation-backed attributes: groups.value (users) and members.value (groups)
    // ---------------------------------------------------------------------------------------------

    @Test
    public void relationBackedGroupsAndMembers() {
        assertThat(allUsers("groups.value eq null"), empty());
        assertThat(allUsers("groups.value ne null"), empty());
        assertThat(users("groups.value pr"), containsInAnyOrder(ALICE));
        assertThat(users("not (groups.value pr)"), containsInAnyOrder(BOB, CAROL));
        assertThat(users("groups.value ne \"" + groupAId + "\""), empty());
        assertThat(users("not (groups.value eq \"" + groupAId + "\")"), containsInAnyOrder(BOB, CAROL));

        assertThat(allGroups("displayName eq null"), empty());
        assertThat(allGroups("displayName ne null"), empty());
        assertThat(allGroups("members.value eq null"), empty());
        assertThat(allGroups("members.value ne null"), empty());
        assertThat(groups("members.value pr"), containsInAnyOrder(GROUP_A));
        assertThat(groups("not (members.value pr)"), containsInAnyOrder(GROUP_EMPTY));
        assertThat(groups("members.value ne \"" + aliceId + "\""), empty());
        assertThat(groups("not (members.value eq \"" + aliceId + "\")"), containsInAnyOrder(GROUP_EMPTY));
    }

    // ---------------------------------------------------------------------------------------------
    // null with any operator other than eq/ne -> 400 invalidFilter
    // ---------------------------------------------------------------------------------------------

    @Test
    public void nullWithOtherOperatorsIsRejected() {
        for (String filter : List.of("userName co null", "userName sw null", "userName ew null",
                "meta.created gt null", "meta.created ge null", "meta.created lt null", "meta.created le null",
                "active gt null")) {
            ScimClientException e = assertThrows(ScimClientException.class, () -> client.users().getAll(filter), filter);
            assertNotNull(e.getError(), filter);
            System.out.println("[NULLSEM] filter=" + filter + " -> " + e.getError().getStatus() + " " + e.getError().getScimType()
                    + " : " + e.getError().getDetail());
            assertThat(filter, e.getError().getScimType(), is("invalidFilter"));
            assertThat(filter, e.getError().getDetail(), containsString("does not accept null values"));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // exploratory: in-memory PATCH value-path filter with eq null
    // ---------------------------------------------------------------------------------------------

    @Test
    public void patchValuePathWithNonMatchingLiteral() {
        // control experiment: does the emails remover honour the value-path filter at all?
        for (String path : List.of("emails[value eq \"does-not-match@nulltest.org\"]", "groups[value eq \"does-not-exist\"]")) {
            try {
                client.users().patch(aliceId, PatchRequest.create().remove(path).build());
                User patched = client.users().get(aliceId);
                System.out.println("[NULLSEM] PATCH remove " + path + " -> OK; email=" + patched.getEmail()
                        + " groups=" + (patched.getGroups() == null ? null : patched.getGroups().size()));
            } catch (ScimClientException e) {
                System.out.println("[NULLSEM] PATCH remove " + path + " -> " + (e.getError() == null ? e.getMessage()
                        : e.getError().getStatus() + " " + e.getError().getScimType() + " : " + e.getError().getDetail()));
            }
        }
        User alice = client.users().get(aliceId, List.of("userName", "emails", "groups"));
        System.out.println("[NULLSEM] alice after non-matching PATCH: email=" + alice.getEmail() + " groups="
                + (alice.getGroups() == null ? null : alice.getGroups().size()));
    }

    @Test
    public void patchValuePathWithEqNull() {
        for (String path : List.of("emails[value eq null]", "groups[value eq null]")) {
            try {
                client.users().patch(aliceId, PatchRequest.create().remove(path).build());
                User patched = client.users().get(aliceId);
                System.out.println("[NULLSEM] PATCH remove " + path + " -> OK; email=" + patched.getEmail()
                        + " groups=" + (patched.getGroups() == null ? null : patched.getGroups().size()));
            } catch (ScimClientException e) {
                System.out.println("[NULLSEM] PATCH remove " + path + " -> " + (e.getError() == null ? e.getMessage()
                        : e.getError().getStatus() + " " + e.getError().getScimType() + " : " + e.getError().getDetail()));
            }
        }
        User alice = client.users().get(aliceId);
        System.out.println("[NULLSEM] alice after PATCH: email=" + alice.getEmail() + " groups="
                + (alice.getGroups() == null ? null : alice.getGroups().size()));
    }

    // ---------------------------------------------------------------------------------------------

    private Set<String> users(String filter) {
        return names(client.users().getAll("userName sw \"" + PREFIX + "\" and (" + filter + ")"), filter);
    }

    private Set<String> allUsers(String filter) {
        return names(client.users().getAll(filter), filter);
    }

    private Set<String> names(ListResponse<User> response, String filter) {
        assertNotNull(response);
        Set<String> names = response.getResources().stream().map(User::getUserName).collect(Collectors.toCollection(TreeSet::new));
        System.out.println("[NULLSEM] users filter=" + filter + " -> total " + response.getTotalResults() + " " + names);
        return names;
    }

    private Set<String> groups(String filter) {
        return groupNames(client.groups().getAll("displayName sw \"" + PREFIX + "\" and (" + filter + ")"), filter);
    }

    private Set<String> allGroups(String filter) {
        return groupNames(client.groups().getAll(filter), filter);
    }

    private Set<String> groupNames(ListResponse<Group> response, String filter) {
        assertNotNull(response);
        Set<String> names = response.getResources().stream().map(Group::getDisplayName).collect(Collectors.toCollection(TreeSet::new));
        System.out.println("[NULLSEM] groups filter=" + filter + " -> total " + response.getTotalResults() + " " + names);
        return names;
    }

    private User createUser(String username, String givenName, String familyName, String email, boolean active, String department) {
        User user = new User();
        user.setUserName(username);
        user.setFirstName(givenName);
        user.setLastName(familyName);
        user.setEmail(email);
        user.setActive(active);
        if (department != null) {
            EnterpriseUser enterpriseUser = new EnterpriseUser();
            enterpriseUser.setDepartment(department);
            user.setEnterpriseUser(enterpriseUser);
        }
        user = client.users().create(user);
        assertNotNull(user);
        userIdsToRemove.add(user.getId());
        return user;
    }

    private String createGroup(String displayName) {
        Group group = new Group();
        group.setDisplayName(displayName);
        group = client.groups().create(group);
        assertNotNull(group);
        groupIdsToRemove.add(group.getId());
        return group.getId();
    }
}
