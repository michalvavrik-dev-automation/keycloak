package org.keycloak.it.cli.dist;

import io.quarkus.test.junit.main.Launch;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.RawDistOnly;

@DistributionTest
@RawDistOnly(reason = "Containers are immutable")
@Tag(DistributionTest.SMOKE)
public class MissingDbKindCrashTest {

    // Note: We do NOT provide --db-kind-client-store here! And it's removed from quarkus.properties!
    @Test
    @Launch({"start-dev", "--db=dev-file", "--db-kind-new-user-store=dev-mem", "--db-kind-pu-without-dialect-store=dev-mem"})
    void testMissingDbKind(CLIResult cliResult) {
        cliResult.assertStartedDevMode();
    }
}
