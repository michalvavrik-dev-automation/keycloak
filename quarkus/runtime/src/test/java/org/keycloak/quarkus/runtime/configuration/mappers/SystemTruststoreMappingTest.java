/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.quarkus.runtime.configuration.mappers;

import java.util.Map;

import org.keycloak.quarkus.runtime.configuration.AbstractConfigurationTest;

import org.junit.Test;

/**
 * RED-phase config-mapping tests for the reloadable system truststore (issue #51680).
 *
 * <p>These assert that {@code --truststore-paths} entries are turned into one Quarkus TLS
 * registry configuration ("bucket") per user-supplied file — a single shared PEM bucket for all
 * PEM material, and one bucket per PKCS12/JKS file. None of that mapping exists yet, so every
 * {@code assertExternalConfig(...)} below fails because the expected {@code quarkus.tls.*}
 * property is <em>absent</em> (i.e. the bucket-generating ConfigSource is not implemented) — NOT
 * because of an unknown option or a broken setup. These tests require no production changes to
 * compile or run.
 *
 * <p>DESIGN ENCODED HERE FOR REVIEW — bucket naming scheme (adjust before implementation if desired):
 * <ul>
 *   <li>all PEM files share one bucket: {@code keycloak-system-truststore}</li>
 *   <li>each PKCS12/JKS file gets its own bucket keyed by its 0-based index within
 *       {@code --truststore-paths}: {@code keycloak-system-truststore-<index>}</li>
 * </ul>
 */
public class SystemTruststoreMappingTest extends AbstractConfigurationTest {

    // --- encoded bucket-naming design (test-local; no production constant added in the red phase) ---
    static final String PEM_BUCKET = "quarkus.tls.\"keycloak-system-truststore\".";

    static String fileBucket(int truststorePathsIndex) {
        return "quarkus.tls.\"keycloak-system-truststore-" + truststorePathsIndex + "\".";
    }

    @Test
    public void singlePemFileMappedToPemBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca.pem");
        assertExternalConfig(PEM_BUCKET + "trust-store.pem.certs", "/certs/ca.pem");
        assertExternalConfigNull(fileBucket(0) + "trust-store.p12.path");
    }

    @Test
    public void multiplePemFilesFoldedIntoOnePemCertsList() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca-a.pem,/certs/ca-b.crt,/certs/ca-c.ca");
        // order preserved so merge order (last-wins) is deterministic
        assertExternalConfig(PEM_BUCKET + "trust-store.pem.certs", "/certs/ca-a.pem,/certs/ca-b.crt,/certs/ca-c.ca");
    }

    @Test
    public void pkcs12FileMappedToOwnBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/store.p12");
        assertExternalConfig(fileBucket(0) + "trust-store.p12.path", "/certs/store.p12");
        assertExternalConfigNull(PEM_BUCKET + "trust-store.pem.certs");
    }

    @Test
    public void jksFileMappedToOwnBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/store.jks");
        assertExternalConfig(fileBucket(0) + "trust-store.jks.path", "/certs/store.jks");
        assertExternalConfigNull(PEM_BUCKET + "trust-store.pem.certs");
    }

    @Test
    public void mixedPemAndBinaryFilesSplitAcrossBuckets() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca.pem,/certs/store.p12,/certs/legacy.jks");
        assertExternalConfig(Map.of(
                PEM_BUCKET + "trust-store.pem.certs", "/certs/ca.pem",
                fileBucket(1) + "trust-store.p12.path", "/certs/store.p12",
                fileBucket(2) + "trust-store.jks.path", "/certs/legacy.jks"
        ));
        // the PEM entry must not leak into a per-file bucket, and binaries must not land in the PEM bucket
        assertExternalConfigNull(fileBucket(0) + "trust-store.p12.path");
        assertExternalConfigNull(fileBucket(1) + "trust-store.pem.certs");
    }

    @Test
    public void noTruststorePathsProducesNoBuckets() {
        createConfigFromCliArguments();
        assertExternalConfigNull(PEM_BUCKET + "trust-store.pem.certs");
        assertExternalConfigNull(fileBucket(0) + "trust-store.p12.path");
    }
}
