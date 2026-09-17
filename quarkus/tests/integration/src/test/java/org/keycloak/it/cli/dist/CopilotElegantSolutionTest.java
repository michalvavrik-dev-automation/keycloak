package org.keycloak.it.cli.dist;

import io.quarkus.test.junit.main.Launch;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.RawDistOnly;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DistributionTest
@RawDistOnly(reason = "Containers are immutable")
@Tag(DistributionTest.SMOKE)
public class CopilotElegantSolutionTest {

    @Test
    @Launch({"start-dev", "--db=dev-file", "--log-level=org.hibernate.orm.jpa:debug,org.keycloak.quarkus.deployment:debug", "--db-kind-new-user-store=dev-mem", "--db-kind-client-store=dev-file", "--db-kind-pu-without-dialect-store=dev-mem"})
    void explicitMappingFileWorks(CLIResult cliResult) {
        String output = cliResult.getOutput();
        String withoutDialectBlock = extractPersistenceUnitBlock(output, "pu-without-dialect-store");
        
        // This PU has NO classes, but it DOES have <mapping-file>META-INF/orm.xml</mapping-file>
        // It should successfully get the OrmMappedEntity!
        assertTrue(withoutDialectBlock != null && withoutDialectBlock.contains("com.acme.provider.legacy.jpa.entity.OrmMappedEntity"),
                "OrmMappedEntity should be present when explicitly mapped, even with no <class> tags");
    }

    private static String extractPersistenceUnitBlock(String output, String puName) {
        String marker = "HHH008541: PersistenceUnitInfo [";
        String nameToken = "name: " + puName;
        int idx = 0;
        while ((idx = output.indexOf(marker, idx)) != -1) {
            int nextBlock = output.indexOf(marker, idx + marker.length());
            String block = nextBlock == -1 ? output.substring(idx) : output.substring(idx, nextBlock);
            if (block.contains(nameToken)) {
                return block;
            }
            idx += marker.length();
        }
        return null;
    }
}
