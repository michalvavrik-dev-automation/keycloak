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
package org.keycloak.it.cli.dist;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLException;

import org.keycloak.it.junit5.extension.CLIResult;
import org.keycloak.it.junit5.extension.DistributionTest;
import org.keycloak.it.junit5.extension.KeycloakRunner;
import org.keycloak.it.junit5.extension.RawDistOnly;
import org.keycloak.it.junit5.extension.StopServer.Mode;
import org.keycloak.it.utils.RawKeycloakDistribution;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.SocketAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the post-quantum cryptography (PQC) modes of the HTTPS listeners, see the {@code pqc-http-in} and
 * {@code pqc-http-management} options.
 * <p>
 * Negotiating a hybrid post-quantum key exchange requires a Java runtime supporting it, such as OpenJDK 27. The server
 * is started with the same Java runtime as the tests, and the tests that need the support are skipped otherwise.
 */
@DistributionTest(stopServer = Mode.MANUAL, enableTls = true, defaultOptions = { "--db=dev-file", "--health-enabled=true" })
@RawDistOnly(reason = "We do not test TLS in containers")
public class PqcDistTest {

    private static final int HTTPS_PORT = 8443;
    private static final int MANAGEMENT_PORT = 9000;
    private static final String HTTPS_PATH = "/realms/master";
    private static final String MANAGEMENT_PATH = "/health";

    private static final List<String> HYBRID_PQC_GROUPS = List.of("X25519MLKEM768");
    private static final List<String> CLASSICAL_GROUPS = List.of("x25519", "secp256r1");

    private Vertx vertx;

    @BeforeEach
    public void createVertx() {
        vertx = Vertx.vertx();
    }

    @AfterEach
    public void closeVertx() throws Exception {
        vertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }

    static boolean isPqcKeyExchangeAvailable() {
        return JdkSSLEngineOptions.isPqcAvailable();
    }

    @Test
    @EnabledIf("isPqcKeyExchangeAvailable")
    public void enforceHybridRejectsClassicalKeyExchange(KeycloakRunner runner) throws Exception {
        CLIResult result = start(runner, "--pqc-http-in=enforce-hybrid");
        result.assertStartedDevMode();

        assertHybridKeyExchangeEnforced(HTTPS_PORT, HTTPS_PATH);
        // the management interface inherits the mode
        assertHybridKeyExchangeEnforced(MANAGEMENT_PORT, MANAGEMENT_PATH);
    }

    @Test
    @EnabledIf("isPqcKeyExchangeAvailable")
    public void managementModeOverridesInheritedMode(KeycloakRunner runner) throws Exception {
        CLIResult result = start(runner, "--pqc-http-in=enforce-hybrid", "--pqc-http-management=optional");
        result.assertStartedDevMode();

        assertHybridKeyExchangeEnforced(HTTPS_PORT, HTTPS_PATH);
        assertClassicalKeyExchangeAccepted(MANAGEMENT_PORT, MANAGEMENT_PATH);

        result = start(runner, "--pqc-http-management=enforce-hybrid");
        result.assertStartedDevMode();

        assertClassicalKeyExchangeAccepted(HTTPS_PORT, HTTPS_PATH);
        assertHybridKeyExchangeEnforced(MANAGEMENT_PORT, MANAGEMENT_PATH);
    }

    @Test
    public void optionalModeAcceptsClassicalKeyExchange(KeycloakRunner runner) throws Exception {
        CLIResult result = start(runner, "--pqc-http-in=optional");
        result.assertStartedDevMode();

        assertClassicalKeyExchangeAccepted(HTTPS_PORT, HTTPS_PATH);
        assertClassicalKeyExchangeAccepted(MANAGEMENT_PORT, MANAGEMENT_PATH);

        if (isPqcKeyExchangeAvailable()) {
            assertEquals(200, request(HTTPS_PORT, HTTPS_PATH, HYBRID_PQC_GROUPS),
                    "Client offering a hybrid post-quantum group should be accepted");
            assertEquals(200, request(MANAGEMENT_PORT, MANAGEMENT_PATH, HYBRID_PQC_GROUPS),
                    "Client offering a hybrid post-quantum group should be accepted");
        }
    }

    @Test
    @DisabledIf("isPqcKeyExchangeAvailable")
    public void enforceHybridRejectedWhenNotSupportedByRuntime(KeycloakRunner runner) {
        CLIResult result = start(runner, "--pqc-http-in=enforce-hybrid");
        result.assertError("The 'enforce-hybrid' PQC mode set by the 'pqc-http-in' option requires a TLS engine supporting hybrid post-quantum key exchange, which is not available in the current Java runtime.");

        result = start(runner, "--pqc-http-management=enforce-hybrid");
        result.assertError("The 'enforce-hybrid' PQC mode set by the 'pqc-http-management' option requires a TLS engine supporting hybrid post-quantum key exchange, which is not available in the current Java runtime.");
    }

    @Test
    public void enforceHybridRequiresTlsV13(KeycloakRunner runner) {
        CLIResult result = start(runner, "--pqc-http-in=enforce-hybrid", "--https-protocols=TLSv1.2");
        result.assertError("The 'enforce-hybrid' PQC mode set by the 'pqc-http-in' option requires the 'TLSv1.3' protocol to be enabled by the 'https-protocols' option.");
    }

    private static CLIResult start(KeycloakRunner runner, String... args) {
        // run the server with the same Java runtime as the tests, so that both sides have the same TLS capabilities
        runner.getDistribution(RawKeycloakDistribution.class).setEnvVar("JAVA_HOME", System.getProperty("java.home"));
        List<String> allArgs = new ArrayList<>();
        allArgs.add("start-dev");
        allArgs.addAll(List.of(args));
        return runner.run(allArgs);
    }

    private void assertHybridKeyExchangeEnforced(int port, String path) throws Exception {
        assertEquals(200, request(port, path, HYBRID_PQC_GROUPS),
                "Client offering a hybrid post-quantum group should be accepted on port " + port);
        Exception e = assertThrows(Exception.class, () -> request(port, path, CLASSICAL_GROUPS),
                "Client offering only classical groups should be rejected on port " + port);
        assertTrue(hasCause(e, SSLException.class), () -> "Expected a TLS handshake failure on port " + port + " but got: " + e);
    }

    private void assertClassicalKeyExchangeAccepted(int port, String path) throws Exception {
        assertEquals(200, request(port, path, CLASSICAL_GROUPS),
                "Client offering only classical groups should be accepted on port " + port);
    }

    private int request(int port, String path, List<String> keyExchangeGroups) throws Exception {
        HttpClientOptions options = new HttpClientOptions()
                .setSsl(true)
                .setTrustAll(true)
                .setVerifyHost(false);
        options.getSslOptions().setKeyExchangeGroups(keyExchangeGroups);
        HttpClient client = vertx.createHttpClient(options);
        try {
            return client.request(new RequestOptions()
                            .setServer(SocketAddress.inetSocketAddress(port, "localhost"))
                            .setPort(port).setSsl(true).setURI(path).setMethod(HttpMethod.GET))
                    .compose(HttpClientRequest::send)
                    .toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS)
                    .statusCode();
        } finally {
            client.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    private static boolean hasCause(Throwable throwable, Class<? extends Throwable> type) {
        for (Throwable cause = throwable; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return true;
            }
        }
        return false;
    }
}
