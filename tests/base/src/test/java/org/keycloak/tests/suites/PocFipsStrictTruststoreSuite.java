package org.keycloak.tests.suites;

import org.keycloak.common.crypto.FipsMode;
import org.keycloak.testframework.injection.SuiteSupport;
import org.keycloak.tests.truststore.TruststoreReloadTest;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

// POC-only (dev-auto/keycloak-51680/fips-ci): runs TruststoreReloadTest under FIPS strict, reusing
// FipsStrictTestSuite's server/certificate config so the FIPS signal is scoped to the truststore reload work.
@Suite
@SelectClasses({ TruststoreReloadTest.class })
public class PocFipsStrictTruststoreSuite {

    @BeforeSuite
    public static void beforeSuite() {
        SuiteSupport.startSuite()
                .registerServerConfig(FipsStrictTestSuite.FipsStrictServerConfig.class)
                .registerSupplierConfig("certificates", FipsStrictTestSuite.FipsStrictCertificatesConfig.class)
                .registerSupplierConfig("crypto", "fips", FipsMode.STRICT.name());
    }

    @AfterSuite
    public static void afterSuite() {
        SuiteSupport.stopSuite();
    }
}
