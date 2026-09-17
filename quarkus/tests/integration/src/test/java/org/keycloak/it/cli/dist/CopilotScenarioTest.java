package org.keycloak.it.cli.dist;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.RawDistOnly;
import org.keycloak.it.junit5.extension.TestProvider;
import com.acme.provider.legacy.jpa.entity.CustomJpaEntityProvider;

import io.quarkus.test.junit.main.Launch;

@DistributionTest
@RawDistOnly(reason = "Containers are immutable")
@TestProvider(CustomJpaEntityProvider.class)
public class CopilotScenarioTest {

    @Test
    @Launch({ "start-dev", "--db=dev-mem", 
              "--db-kind-new-user-store=dev-mem", 
              "--db-kind-client-store=dev-mem", 
              "--db-kind-pu-without-dialect-store=dev-mem", 
              "--log-level=org.hibernate.orm.jpa:DEBUG" })
    void testEmptyPuGetsImplicitOrmXml(CLIResult cliResult) {
        String logOutput = cliResult.getOutput();
        int puStartIndex = logOutput.indexOf("name: pu-without-dialect-store");
        assertTrue(puStartIndex >= 0, "PU must have started");
        
        int puEndIndex = logOutput.indexOf("HHH008541", puStartIndex);
        if (puEndIndex == -1) puEndIndex = logOutput.length();
        
        String puBlock = logOutput.substring(puStartIndex, puEndIndex);
        
        assertTrue(puBlock.contains("com.acme.provider.legacy.jpa.entity.OrmMappedEntity"), 
            "Copilot is right: A PU with zero <class> tags should STILL get the implicit orm.xml entities!");
    }
}
