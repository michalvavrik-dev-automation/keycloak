package org.keycloak.quarkus.runtime.configuration.mappers;

import java.io.File;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.def.DefaultCryptoProvider;
import org.keycloak.quarkus.runtime.configuration.AbstractConfigurationTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class SystemTruststoreMappingTest extends AbstractConfigurationTest {

    private static final char[] STORE_PASSWORD = "password".toCharArray();

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private CryptoProvider originalCryptoProvider;

    @Before
    public void useDefaultCryptoProvider() {
        originalCryptoProvider = CryptoIntegration.isInitialised() ? CryptoIntegration.getProvider() : null;
        CryptoIntegration.setProvider(new DefaultCryptoProvider());
    }

    @After
    public void restoreCryptoProvider() {
        CryptoIntegration.setProvider(originalCryptoProvider);
    }

    @Test
    public void singlePemFileMapsToPemBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca.pem");
        assertExternalConfig(pemCerts(), "/certs/ca.pem");
    }

    @Test
    public void multiplePemFilesFoldIntoOnePemBucketPreservingOrder() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca-a.pem,/certs/ca-b.crt,/certs/ca-c.ca");
        assertExternalConfig(pemCerts(), "/certs/ca-a.pem,/certs/ca-b.crt,/certs/ca-c.ca");
    }

    @Test
    public void fourPkcs12FilesEachMapToTheirOwnBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/a.p12,/certs/b.p12,/certs/c.p12,/certs/d.p12");
        assertExternalConfig(Map.of(
                pkcs12Path(0), "/certs/a.p12",
                pkcs12Path(1), "/certs/b.p12",
                pkcs12Path(2), "/certs/c.p12",
                pkcs12Path(3), "/certs/d.p12"
        ));
        assertExternalConfigNull(pkcs12Path(4));
        assertExternalConfigNull(pemCerts());
    }

    @Test
    public void threeJksFilesEachMapToTheirOwnBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/a.jks,/certs/b.jks,/certs/c.jks");
        assertExternalConfig(Map.of(
                jksPath(0), "/certs/a.jks",
                jksPath(1), "/certs/b.jks",
                jksPath(2), "/certs/c.jks"
        ));
        assertExternalConfigNull(jksPath(3));
    }

    @Test
    public void bcfksFileMapsToOtherBucketWithType() {
        createConfigFromCliArguments("--truststore-paths=/certs/trust.bcfks");
        assertExternalConfig(Map.of(
                otherPath(0), "/certs/trust.bcfks",
                otherType(0), "BCFKS"
        ));
    }

    @Test
    public void allPkcs12ExtensionsMapToPkcs12Buckets() {
        createConfigFromCliArguments("--truststore-paths=/certs/a.p12,/certs/b.pfx,/certs/c.pkcs12");
        assertExternalConfig(Map.of(
                pkcs12Path(0), "/certs/a.p12",
                pkcs12Path(1), "/certs/b.pfx",
                pkcs12Path(2), "/certs/c.pkcs12"
        ));
    }

    @Test
    public void mixedFormatsSplitAcrossBucketsByType() {
        createConfigFromCliArguments("--truststore-paths="
                + "/certs/ca.pem,/certs/a.jks,/certs/b.p12,/certs/c.pem,/certs/d.jks,/certs/e.p12,/certs/trust.bcfks");
        assertExternalConfig(Map.of(
                pemCerts(), "/certs/ca.pem,/certs/c.pem",
                jksPath(0), "/certs/a.jks",
                jksPath(1), "/certs/d.jks",
                pkcs12Path(0), "/certs/b.p12",
                pkcs12Path(1), "/certs/e.p12",
                otherPath(0), "/certs/trust.bcfks",
                otherType(0), "BCFKS"
        ));
        assertExternalConfigNull(jksPath(2));
        assertExternalConfigNull(pkcs12Path(2));
    }

    @Test
    public void noTruststorePathsProducesNoBuckets() {
        createConfigFromCliArguments();
        assertExternalConfigNull(pemCerts());
        assertExternalConfigNull(pkcs12Path(0));
        assertExternalConfigNull(jksPath(0));
    }

    @Test
    public void reloadPeriodAppliesToEachBucket() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca.pem,/certs/store.p12",
                "--truststore-paths-reload-period=30s");
        assertExternalConfig(bucket("", "reload-period"), "30s");
        assertExternalConfig(bucket("-pkcs12-0", "reload-period"), "30s");
    }

    @Test
    public void reloadPeriodAbsentWhenNotConfigured() {
        createConfigFromCliArguments("--truststore-paths=/certs/ca.pem,/certs/store.p12");
        assertExternalConfigNull(bucket("", "reload-period"));
        assertExternalConfigNull(bucket("-pkcs12-0", "reload-period"));
    }

    @Test
    public void directoryOfPemFilesFoldsIntoPemBucket() throws Exception {
        File directory = temporaryFolder.newFolder("certs");
        File first = writePemCertificate(new File(directory, "ca-a.pem"));
        File second = writePemCertificate(new File(directory, "ca-b.pem"));

        createConfigFromCliArguments("--truststore-paths=" + directory.getAbsolutePath());

        assertExternalConfig(pemCerts(), sortedPaths(first, second));
    }

    @Test
    public void directoryWithMixedFormatsSplitsAcrossBuckets() throws Exception {
        File directory = temporaryFolder.newFolder("certs");
        File pem = writePemCertificate(new File(directory, "ca.pem"));
        File pkcs12 = writeKeyStore(new File(directory, "store.p12"), "PKCS12");
        File jks = writeKeyStore(new File(directory, "legacy.jks"), "JKS");

        createConfigFromCliArguments("--truststore-paths=" + directory.getAbsolutePath());

        assertExternalConfig(Map.of(
                pemCerts(), pem.getAbsolutePath(),
                pkcs12Path(0), pkcs12.getAbsolutePath(),
                jksPath(0), jks.getAbsolutePath()
        ));
    }

    @Test
    public void directoryIgnoresNonCertificateFiles() throws Exception {
        File directory = temporaryFolder.newFolder("certs");
        File pem = writePemCertificate(new File(directory, "ca.pem"));
        Files.writeString(new File(directory, "notes.txt").toPath(), "not a certificate");

        createConfigFromCliArguments("--truststore-paths=" + directory.getAbsolutePath());

        assertExternalConfig(pemCerts(), pem.getAbsolutePath());
    }

    @Test
    public void directoryAndExplicitPathsCombine() throws Exception {
        File directory = temporaryFolder.newFolder("certs");
        File pkcs12 = writeKeyStore(new File(directory, "store.p12"), "PKCS12");

        createConfigFromCliArguments("--truststore-paths=/explicit/x.pem," + directory.getAbsolutePath());

        assertExternalConfig(Map.of(
                pemCerts(), "/explicit/x.pem",
                pkcs12Path(0), pkcs12.getAbsolutePath()
        ));
    }

    private File writePemCertificate(File file) throws Exception {
        Files.writeString(file.toPath(), PemUtils.addCertificateBeginEnd(PemUtils.encodeCertificate(selfSignedCertificate())));
        return file;
    }

    private File writeKeyStore(File file, String type) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", selfSignedCertificate());
        try (OutputStream out = Files.newOutputStream(file.toPath())) {
            keyStore.store(out, STORE_PASSWORD);
        }
        return file;
    }

    private static X509Certificate selfSignedCertificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return CryptoIntegration.getProvider().getCertificateUtils()
                .generateV1SelfSignedCertificate(generator.generateKeyPair(), "test");
    }

    private static String sortedPaths(File... files) {
        return Arrays.stream(files).map(File::getAbsolutePath).sorted().collect(Collectors.joining(","));
    }

    private static String pemCerts() {
        return bucket("", "trust-store.pem.certs");
    }

    private static String pkcs12Path(int index) {
        return bucket("-pkcs12-" + index, "trust-store.p12.path");
    }

    private static String jksPath(int index) {
        return bucket("-jks-" + index, "trust-store.jks.path");
    }

    private static String otherPath(int index) {
        return bucket("-bcfks-" + index, "trust-store.other.path");
    }

    private static String otherType(int index) {
        return bucket("-bcfks-" + index, "trust-store.other.type");
    }

    private static String bucket(String suffix, String leaf) {
        return "quarkus.tls.\"keycloak-system-truststore" + suffix + "\"." + leaf;
    }
}
