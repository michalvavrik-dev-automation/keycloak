package org.keycloak.tests.truststore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.common.util.PemUtils;
import org.keycloak.config.TruststoreOptions;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.truststore.SystemTruststoreReload;
import org.keycloak.truststore.TruststoreBuilder;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Change-detection tests for the reloadable system truststore (issue #51680).
 *
 * <p>The Quarkus TLS-registry timer fires a {@code CertificateUpdatedEvent} on <em>every</em>
 * {@code truststore-paths-reload-period}, whether or not any source file changed (Quarkus'
 * {@code VertxCertificateHolder.reload()} returns {@code true} on any successful re-read; it does not diff
 * content). To avoid pointlessly re-merging + re-notifying every consumer on every tick, the reload path is
 * expected to fingerprint its source files (the {@code truststore-paths} files + the default cacerts) and
 * <strong>skip</strong> the re-merge when the fingerprint is unchanged, proceeding only on a real change.
 *
 * <p><strong>RED-first.</strong> This class is written before the change-detection implementation exists.
 * It depends on a single observability hook that must be added to production (see below); once that hook is
 * present but change-detection is not, the idle ({@code *DoesNotReload}) tests fail because the counter keeps
 * climbing every period. Once change-detection lands, they pass. The change ({@code *TriggersReload}) tests
 * are positive controls that pass in both states.
 *
 * <p><strong>Observability hook this test depends on</strong> (must be implemented to match):
 * <pre>
 *   // in org.keycloak.truststore.SystemTruststoreReload
 *   public static long reloadCount();
 * </pre>
 * Semantics: a monotonically increasing counter (backed by an {@code AtomicLong}) that is incremented
 * <em>exactly once each time {@link SystemTruststoreReload#reload} actually re-merges the truststore</em>
 * (i.e. a real change was detected and consumers were notified). It must <em>not</em> be incremented when a
 * reload is skipped because the source fingerprint was unchanged. Before change-detection exists it therefore
 * increments on every timer tick (every reload re-merges); after change-detection it increments only on a
 * genuine source change.
 *
 * <p>Because the counter is global (one truststore, one merge), an idle assertion inherently proves that
 * <em>no</em> configured source shape false-fires while stable; the per-shape idle methods document that each
 * listed shape (PEM / no-MAC PKCS12 / empty-password-MAC PKCS12 / directory / mixed) is present and stable
 * during the observed window. The change methods then prove the fingerprint detects a real change in each
 * shape. "A consumer reflects the new CA" is asserted against the on-disk merged truststore that reload
 * rewrites (read via the {@code javax.net.ssl.trustStore*} system properties), which is exactly the artifact
 * every truststore consumer loads from.
 */
@KeycloakIntegrationTest(config = SystemTruststoreChangeDetectionTest.ServerConfig.class)
public class SystemTruststoreChangeDetectionTest {

    private static final Path TMP = Path.of(System.getProperty("java.io.tmpdir"));

    // Distinct file names from TruststoreReloadTest: both classes live in the same module and share this tmp
    // directory, so they must not collide on the source files they mutate.
    private static final Path CHANGEDET_PEM = TMP.resolve("kc-it-changedet.pem");
    private static final Path CHANGEDET_NOMAC_P12 = TMP.resolve("kc-it-changedet-nomac.p12");
    private static final Path CHANGEDET_EMPTYMAC_P12 = TMP.resolve("kc-it-changedet-emptymac.p12");
    private static final Path CHANGEDET_DIR = TMP.resolve("kc-it-changedet-dir");
    private static final Path CHANGEDET_DIR_BASELINE = CHANGEDET_DIR.resolve("dir-a.pem");
    private static final Path CHANGEDET_DIR_EXTRA = CHANGEDET_DIR.resolve("dir-b.pem");
    private static final Path CHANGEDET_MIXED_PEM = TMP.resolve("kc-it-changedet-mixed.pem");
    private static final Path CHANGEDET_MIXED_P12 = TMP.resolve("kc-it-changedet-mixed.p12");

    private static final Duration RELOAD_PERIOD = Duration.ofSeconds(2);
    // "Skipped" must hold across at least ~3 reload periods.
    private static final Duration IDLE_WINDOW = RELOAD_PERIOD.multipliedBy(3);
    private static final Duration RELOAD_TIMEOUT = Duration.ofSeconds(20);

    private static final AtomicInteger CA_SEQUENCE = new AtomicInteger();

    static {
        // These truststore-paths source files must exist before the server boots, so the controlling test JVM
        // seeds them here in <clinit>. When runOnServer ships this class to the server it is reloaded by the
        // remote TestClassLoader and this initializer runs a second time there; that server-side run must NOT
        // recreate the sources - doing so overwrites the fresh baselines the running test just wrote (embedded
        // server = same JVM = same java.io.tmpdir = same files), leaving the reload nothing to pick up and
        // making the @BeforeEach settle-wait time out. Guard on the class loader.
        if (runningInControllingTestJvm()) {
            try {
                // Every truststore-paths source must exist and be loadable when the server boots; seed them empty
                // and let each test populate its own fresh baseline in @BeforeEach.
                Files.createDirectories(CHANGEDET_DIR);
                writeFileAtomically(CHANGEDET_PEM, new byte[0]);
                writeFileAtomically(CHANGEDET_MIXED_PEM, new byte[0]);
                writeFileAtomically(CHANGEDET_DIR_BASELINE, new byte[0]);
                writeFileAtomically(CHANGEDET_NOMAC_P12, pkcs12Bytes(null));
                writeFileAtomically(CHANGEDET_MIXED_P12, pkcs12Bytes(null));
                writeFileAtomically(CHANGEDET_EMPTYMAC_P12, pkcs12Bytes("".toCharArray()));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    // True only in the controlling test JVM. Server-side (runOnServer) this class is loaded by the test
    // framework's remote TestClassLoader; there the shared source files must never be (re)written.
    private static boolean runningInControllingTestJvm() {
        return !"TestClassLoader".equals(
                SystemTruststoreChangeDetectionTest.class.getClassLoader().getClass().getSimpleName());
    }

    @InjectRunOnServer(permittedPackages = "org.keycloak.tests.truststore")
    RunOnServerClient runOnServer;

    private String pemBaselineSubject;
    private String noMacBaselineSubject;
    private String emptyMacBaselineSubject;
    private String mixedPemBaselineSubject;
    private String mixedP12BaselineSubject;
    private String dirBaselineSubject;

    /**
     * Bring every source to a fresh, unique baseline and wait until the merged on-disk store reflects them
     * all. The merge that contains every fresh baseline must have read every source in its final state, so the
     * change-detection fingerprint is settled: subsequent idle ticks must skip. Using a fresh CA per source
     * per test also guarantees the baseline write is a real change (so the fingerprint is definitely recorded)
     * and gives each test unambiguous, unique subjects to assert on.
     */
    @BeforeEach
    void establishSettledBaseline() throws Exception {
        pemBaselineSubject = writePem(CHANGEDET_PEM, generateCa());
        noMacBaselineSubject = writeNoMacPkcs12(CHANGEDET_NOMAC_P12, generateCa());
        emptyMacBaselineSubject = writeEmptyPasswordMacPkcs12(CHANGEDET_EMPTYMAC_P12, generateCa());
        mixedPemBaselineSubject = writePem(CHANGEDET_MIXED_PEM, generateCa());
        mixedP12BaselineSubject = writeNoMacPkcs12(CHANGEDET_MIXED_P12, generateCa());
        // Reset the directory to exactly one known baseline file: drop any extra left over from a failed run
        // and atomically (re)write the baseline, so the baseline file is never momentarily absent.
        Files.deleteIfExists(CHANGEDET_DIR_EXTRA);
        dirBaselineSubject = writePem(CHANGEDET_DIR_BASELINE, generateCa());

        List<String> allBaselines = List.of(pemBaselineSubject, noMacBaselineSubject, emptyMacBaselineSubject,
                mixedPemBaselineSubject, mixedP12BaselineSubject, dirBaselineSubject);
        Awaitility.await("system truststore settles on the fresh baselines")
                .atMost(RELOAD_TIMEOUT).pollInterval(Duration.ofMillis(500))
                .until(() -> generatedStoreSubjects().containsAll(allBaselines));
    }

    // --- 1. Idle = skip (per source shape) -----------------------------------------------------------------

    @Test
    void pemSourceStableDoesNotReload() {
        assertIdleDoesNotReload();
    }

    @Test
    void noMacPkcs12SourceStableDoesNotReload() {
        assertIdleDoesNotReload();
    }

    @Test
    void emptyPasswordMacPkcs12SourceStableDoesNotReload() {
        assertIdleDoesNotReload();
    }

    // --- 2. Real change = fire (per source shape) ----------------------------------------------------------

    @Test
    void pemSourceChangeTriggersReload() throws Exception {
        X509Certificate rotated = generateCa();
        assertRotationDetected(() -> writePem(CHANGEDET_PEM, rotated),
                List.of(subjectOf(rotated)), List.of(pemBaselineSubject));
    }

    @Test
    void noMacPkcs12SourceChangeTriggersReload() throws Exception {
        X509Certificate rotated = generateCa();
        assertRotationDetected(() -> writeNoMacPkcs12(CHANGEDET_NOMAC_P12, rotated),
                List.of(subjectOf(rotated)), List.of(noMacBaselineSubject));
    }

    @Test
    void emptyPasswordMacPkcs12SourceChangeTriggersReload() throws Exception {
        X509Certificate rotated = generateCa();
        assertRotationDetected(() -> writeEmptyPasswordMacPkcs12(CHANGEDET_EMPTYMAC_P12, rotated),
                List.of(subjectOf(rotated)), List.of(emptyMacBaselineSubject));
    }

    // --- 3. Directory source: add / replace / remove are all detected; stable = skip ----------------------

    @Test
    void directorySourceStableDoesNotReload() {
        assertIdleDoesNotReload();
    }

    @Test
    void directorySourceAddReplaceRemoveTriggersReload() throws Exception {
        X509Certificate added = generateCa();
        X509Certificate replacement = generateCa();

        // ADD a new file to the directory: the extra CA must appear, the baseline must remain.
        assertRotationDetected(() -> writePem(CHANGEDET_DIR_EXTRA, added),
                List.of(subjectOf(added), dirBaselineSubject), List.of());

        // REPLACE the baseline file's content: the replacement must appear, the old baseline must go, the
        // added file must remain.
        assertRotationDetected(() -> writePem(CHANGEDET_DIR_BASELINE, replacement),
                List.of(subjectOf(replacement), subjectOf(added)), List.of(dirBaselineSubject));

        // REMOVE the added file: it must disappear even though no remaining file's content changed. This
        // stresses that the fingerprint tracks the directory's file SET, not just the bytes of known files.
        assertRotationDetected(() -> Files.delete(CHANGEDET_DIR_EXTRA),
                List.of(subjectOf(replacement)), List.of(subjectOf(added)));
    }

    // --- 4. Mixed PEM + PKCS12 in truststore-paths: changing either fires; stable = skip ------------------

    @Test
    void mixedPemAndPkcs12SourcesStableDoNotReload() {
        assertIdleDoesNotReload();
    }

    @Test
    void mixedPemSourceChangeTriggersReload() throws Exception {
        X509Certificate rotated = generateCa();
        // The PEM half rotates; the untouched PKCS12 half must still be present.
        assertRotationDetected(() -> writePem(CHANGEDET_MIXED_PEM, rotated),
                List.of(subjectOf(rotated), mixedP12BaselineSubject), List.of(mixedPemBaselineSubject));
    }

    @Test
    void mixedPkcs12SourceChangeTriggersReload() throws Exception {
        X509Certificate rotated = generateCa();
        // The PKCS12 half rotates; the untouched PEM half must still be present.
        assertRotationDetected(() -> writeNoMacPkcs12(CHANGEDET_MIXED_P12, rotated),
                List.of(subjectOf(rotated), mixedPemBaselineSubject), List.of(mixedP12BaselineSubject));
    }

    // --- assertions ---------------------------------------------------------------------------------------

    /**
     * With every source stable, the actual-re-merge counter must not advance across at least ~3 reload
     * periods. RED (no change-detection): the counter climbs every period and this fails at {@code atMost}.
     * GREEN: the counter holds flat for the whole {@link #IDLE_WINDOW}.
     */
    private void assertIdleDoesNotReload() {
        long before = reloadCount();
        Awaitility.await("reload counter stays flat while all sources are stable")
                .pollInterval(Duration.ofMillis(250))
                .during(IDLE_WINDOW)
                .atMost(IDLE_WINDOW.plus(Duration.ofSeconds(8)))
                .until(() -> reloadCount() == before);
    }

    /**
     * Perform a source mutation and assert it is detected: the actual-re-merge counter advances AND the
     * on-disk merged store reflects the new trust set (the expected subjects appear, the rotated-away subjects
     * are gone). Passes in both RED and GREEN, so it is a positive control that the fingerprint never
     * <em>misses</em> a real change.
     */
    private void assertRotationDetected(IoAction mutation, List<String> mustAppear, List<String> mustDisappear)
            throws Exception {
        long before = reloadCount();
        mutation.run();
        Awaitility.await("source change is detected and the merged store is rewritten")
                .atMost(RELOAD_TIMEOUT).pollInterval(Duration.ofMillis(500))
                .until(() -> {
                    if (reloadCount() <= before) {
                        return false;
                    }
                    Set<String> subjects = generatedStoreSubjects();
                    return subjects.containsAll(mustAppear) && Collections.disjoint(subjects, mustDisappear);
                });
    }

    // --- run-on-server probes -----------------------------------------------------------------------------

    private long reloadCount() {
        Long count = runOnServer.fetch(session -> SystemTruststoreReload.reloadCount(), Long.class);
        return count == null ? 0L : count;
    }

    /**
     * Subjects present in the generated on-disk merged truststore that reload rewrites. Reads the store via the
     * {@code javax.net.ssl.trustStore*} system properties, exactly as consumers do. Returns an empty set on any
     * read failure (the store may be momentarily mid-rewrite), letting the caller poll again.
     */
    private Set<String> generatedStoreSubjects() {
        String[] subjects = runOnServer.fetch(session -> {
            List<String> found = new ArrayList<>();
            try {
                KeyStore keyStore = KeystoreUtil.loadKeyStore(
                        System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_KEY),
                        System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_PASSWORD_KEY),
                        System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_TYPE_KEY));
                for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                    Certificate certificate = keyStore.getCertificate(aliases.nextElement());
                    if (certificate instanceof X509Certificate) {
                        found.add(((X509Certificate) certificate).getSubjectX500Principal().getName());
                    }
                }
            } catch (Exception ignored) {
                // store may be mid-rewrite; return what we have and let the caller retry
            }
            return found.toArray(new String[0]);
        }, String[].class);
        return new HashSet<>(Arrays.asList(subjects));
    }

    // --- source writers (atomic, so the reload timer never observes a half-written file) ------------------

    private static String writePem(Path file, X509Certificate certificate) throws Exception {
        writeFileAtomically(file, certificatePem(certificate).getBytes(StandardCharsets.UTF_8));
        return subjectOf(certificate);
    }

    // No-MAC PKCS12: KeyStore#store with a null password.
    private static String writeNoMacPkcs12(Path file, X509Certificate certificate) throws Exception {
        writeFileAtomically(file, pkcs12Bytes(null, certificate));
        return subjectOf(certificate);
    }

    // Empty-password-MAC PKCS12: KeyStore#store with "".toCharArray(), so the store carries an empty MAC.
    private static String writeEmptyPasswordMacPkcs12(Path file, X509Certificate certificate) throws Exception {
        writeFileAtomically(file, pkcs12Bytes("".toCharArray(), certificate));
        return subjectOf(certificate);
    }

    private static byte[] pkcs12Bytes(char[] storePassword, X509Certificate... certificates) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        for (X509Certificate certificate : certificates) {
            keyStore.setCertificateEntry(subjectOf(certificate), certificate);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, storePassword);
        return out.toByteArray();
    }

    private static void writeFileAtomically(Path target, byte[] content) throws IOException {
        Files.createDirectories(target.getParent());
        // Stage in the tmp root (not inside any watched directory) then atomically move into place, so a
        // directory scan never lists a partially written file.
        Path staged = Files.createTempFile(TMP, "kc-it-changedet-", ".tmp");
        try {
            Files.write(staged, content);
            try {
                Files.move(staged, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(staged, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private static X509Certificate generateCa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return CryptoIntegration.getProvider().getCertificateUtils()
                .generateV1SelfSignedCertificate(keyPair, "Change Detection IT CA " + CA_SEQUENCE.incrementAndGet());
    }

    private static String subjectOf(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    private static String certificatePem(X509Certificate certificate) {
        return PemUtils.addCertificateBeginEnd(PemUtils.encodeCertificate(certificate)) + "\n";
    }

    @FunctionalInterface
    private interface IoAction {
        void run() throws Exception;
    }

    static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            // truststore-paths lists every source shape under test: a PEM file, a no-MAC PKCS12, an
            // empty-password-MAC PKCS12, a directory, and a side-by-side PEM+PKCS12 pair - all on one period.
            String paths = String.join(",",
                    CHANGEDET_PEM.toString(),
                    CHANGEDET_NOMAC_P12.toString(),
                    CHANGEDET_EMPTYMAC_P12.toString(),
                    CHANGEDET_DIR.toString(),
                    CHANGEDET_MIXED_PEM.toString(),
                    CHANGEDET_MIXED_P12.toString());
            return config
                    .option(TruststoreOptions.TRUSTSTORE_PATHS.getKey(), paths)
                    .option(TruststoreOptions.TRUSTSTORE_PATHS_RELOAD_PERIOD.getKey(), RELOAD_PERIOD.toSeconds() + "s");
        }
    }
}
