/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.truststore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Stream;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat;
import org.keycloak.common.util.KeystoreUtil.TruststoreFormat;

import org.jboss.logging.Logger;

/**
 * Builds a system-wide truststore from the given config options.
 */
public class TruststoreBuilder {

    public static final String SYSTEM_TRUSTSTORE_KEY = "javax.net.ssl.trustStore";
    public static final String SYSTEM_TRUSTSTORE_PASSWORD_KEY = "javax.net.ssl.trustStorePassword";
    public static final String SYSTEM_TRUSTSTORE_TYPE_KEY = "javax.net.ssl.trustStoreType";
    private static final String CERT_PROTECTION_ALGORITHM_KEY = "keystore.pkcs12.certProtectionAlgorithm";
    public static final String DUMMY_PASSWORD = "keycloakchangeit"; // fips length compliant dummy password
    static final String DEFAULT_CACERTS_PASSWORD = "changeit"; // standard JVM cacerts password; non-approved BCFIPS rejects a null PKCS12 password
    static final String PKCS12 = "PKCS12";

    private static final String KUBERNETES_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    private static final String SERVICE_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt";

    private static final Logger LOGGER = Logger.getLogger(TruststoreBuilder.class);

    private static volatile SystemTruststoreSource systemTruststoreSource;

    private record SystemTruststoreSource(String[] paths, boolean includeDefault, String dataDir, TruststoreFormat preferredType) {
    }

    private static volatile KeyStore systemTruststore;

    private static volatile String lastSourceFingerprint;

    public static void setSystemTruststore(String[] truststores,
                                           boolean trustStoreIncludeDefault,
                                           String dataDir) {
        setSystemTruststore(truststores, trustStoreIncludeDefault, dataDir, null);
    }

    static boolean reloadSystemTruststoreIfChanged() {
        SystemTruststoreSource source = systemTruststoreSource;
        if (source == null) {
            // No source captured yet (configureTruststore has not run, or ran without truststore-paths): there
            // is nothing to reload.
            LOGGER.debug("No system truststore source captured; nothing to reload");
            return false;
        }
        String current = computeSourceFingerprint(source);
        if (current.equals(lastSourceFingerprint)) {
            LOGGER.debugf("System truststore sources unchanged (fingerprint %s); skipping re-merge",
                    fingerprintPrefix(current));
            return false;
        }
        LOGGER.debugf("System truststore sources changed (%s -> %s); re-merging",
                fingerprintPrefix(lastSourceFingerprint), fingerprintPrefix(current));
        // Reuse the fingerprint just computed to detect the change, so a reload does not fingerprint the sources
        // a second time.
        rebuildAndPublish(source, current);
        return true;
    }

    private static String fingerprintPrefix(String fingerprint) {
        if (fingerprint == null) {
            return "none";
        }
        return fingerprint.length() <= 12 ? fingerprint : fingerprint.substring(0, 12);
    }

    // Fingerprint the reload SOURCES (truststore-paths files, files inside directory sources, and the default
    // cacerts) by content, so an unchanged reload interval can be skipped. Never fingerprint the generated
    // output store: re-saving a PKCS12 produces new bytes each time and would self-trigger.
    private static String computeSourceFingerprint(SystemTruststoreSource source) {
        SortedMap<String, String> entries = new TreeMap<>();
        for (String path : source.paths()) {
            addFingerprintEntries(new File(path), entries);
        }
        if (source.includeDefault()) {
            String defaultTrustStore = System.getProperty(SYSTEM_TRUSTSTORE_KEY + ".orig");
            if (defaultTrustStore != null) {
                addFingerprintEntries(new File(defaultTrustStore), entries);
            }
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                digest.update(entry.getKey().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(entry.getValue().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void addFingerprintEntries(File file, SortedMap<String, String> entries) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    addFingerprintEntries(child, entries);
                }
            }
        } else if (file.isFile()) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(Files.readAllBytes(file.toPath()));
                entries.put(file.getAbsolutePath(), HexFormat.of().formatHex(digest.digest()));
            } catch (IOException | NoSuchAlgorithmException e) {
                // unreadable or vanished mid-scan: omit it, so its absence is reflected in the fingerprint
            }
        }
    }

    public static void setSystemTruststore(String[] truststores,
                                           boolean trustStoreIncludeDefault,
                                           String dataDir,
                                           TruststoreFormat preferredTruststoreType) {
        SystemTruststoreSource source = new SystemTruststoreSource(
                truststores.clone(), trustStoreIncludeDefault, dataDir, preferredTruststoreType);
        rebuildAndPublish(source, computeSourceFingerprint(source));
    }

    // Merge the captured sources, persist the generated store, publish it and record its fingerprint. The
    // fingerprint is supplied by the caller so a reload does not fingerprint the sources twice (once to detect
    // the change, once here).
    private static void rebuildAndPublish(SystemTruststoreSource source, String sourceFingerprint) {
        systemTruststoreSource = source;
        TruststoreFormat truststoreType = source.preferredType() == null
                ? getPreferredGeneratedTrustStoreType()
                : source.preferredType();
        KeyStore truststore = createMergedTruststore(source.paths(), source.includeDefault(), truststoreType);

        // save with a dummy password just in case some logic that uses the system properties needs to have one
        File file = saveTruststore(truststore, truststoreType, source.dataDir(), DUMMY_PASSWORD.toCharArray());

        // finally update the system properties
        System.setProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_KEY, file.getAbsolutePath());
        System.setProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_TYPE_KEY, truststoreType.name());
        System.setProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_PASSWORD_KEY, DUMMY_PASSWORD);

        systemTruststore = truststore;
        lastSourceFingerprint = sourceFingerprint;
    }

    public static KeyStore getSystemTruststore() {
        return systemTruststore;
    }

    /**
     * Include the Kubernetes and/or OpenShift service CA truststore paths if enabled and the files exist.
     * Uses the default well-known Kubernetes service account paths.
     *
     * @param trustStores the existing truststore paths
     */
    public static void includeKubernetesTrustStorePaths(List<String> trustStores) {
        includeKubernetesTrustStorePaths(trustStores, KUBERNETES_CA_PATH, SERVICE_CA_PATH);
    }

    /**
     * Include the Kubernetes and/or OpenShift service CA truststore paths if enabled and the files exist.
     *
     * @param trustStores the existing truststore paths
     * @param kubernetesCaPath path to the Kubernetes service account CA certificate
     * @param serviceCaPath path to the OpenShift service CA certificate
     */
    public static void includeKubernetesTrustStorePaths(List<String> trustStores, String kubernetesCaPath, String serviceCaPath) {
        File kubernetesCA = new File(kubernetesCaPath);
        if (kubernetesCA.exists() && kubernetesCA.isFile()) {
            trustStores.add(kubernetesCaPath);
        }

        File serviceCA = new File(serviceCaPath);
        if (serviceCA.exists() && serviceCA.isFile()) {
            trustStores.add(serviceCaPath);
        }
    }

    static File saveTruststore(KeyStore truststore, String dataDir, char[] password) {
        return saveTruststore(truststore, TruststoreFormat.PKCS12, dataDir, password);
    }

    static File saveTruststore(KeyStore truststore, TruststoreFormat truststoreType, String dataDir, char[] password) {
        File file = new File(dataDir, "keycloak-truststore." + truststoreType.getPrimaryExtension());
        file.getParentFile().mkdirs();
        boolean initialCreation = !file.exists();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            if (truststoreType == TruststoreFormat.PKCS12 && initialCreation) {
                String oldValue = System.setProperty(CERT_PROTECTION_ALGORITHM_KEY, "NONE");
                try {
                    truststore.store(fos, password);
                } finally {
                    if (oldValue != null) {
                        System.setProperty(CERT_PROTECTION_ALGORITHM_KEY, oldValue);
                    } else {
                        System.getProperties().remove(CERT_PROTECTION_ALGORITHM_KEY);
                    }
                }
            } else {
                truststore.store(fos, password);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to save truststore: " + file.getAbsolutePath(), e);
        }
        return file;
    }

    static KeyStore createMergedTruststore(String[] truststores, boolean trustStoreIncludeDefault) {
        return createMergedTruststore(truststores, trustStoreIncludeDefault, getPreferredGeneratedTrustStoreType());
    }

    static KeyStore createMergedTruststore(String[] truststores, boolean trustStoreIncludeDefault, TruststoreFormat truststoreType) {
        KeyStore truststore = createTrustStore(truststoreType);

        if (trustStoreIncludeDefault) {
            includeDefaultTruststore(truststore);
        }

        List<String> discoveredFiles = new ArrayList<>();
        mergeFiles(truststores, truststore, true, discoveredFiles);
        if (!discoveredFiles.isEmpty()) {
            LOGGER.infof("Found the following truststore files in the truststore paths %s",
                    discoveredFiles);
        }
        return truststore;
    }

    private static void mergeFiles(String[] truststores, KeyStore truststore, boolean topLevel, List<String> discoveredFiles) {
        for (String file : truststores) {
            File f = new File(file);
            if (f.isDirectory()) {
                mergeFiles(Stream.of(f.listFiles()).map(File::getAbsolutePath).toArray(String[]::new), truststore, false, discoveredFiles);
            } else {
                var format = KeystoreUtil.getKeystoreFormat(file).orElse(null);
                if (format == KeystoreFormat.PKCS12) {
                    mergeTrustStore(truststore, file, loadPkcs12Truststore(file));
                    discoveredFiles.add(f.getAbsolutePath());
                } else if (mergePemFile(truststore, file, topLevel)) {
                    discoveredFiles.add(f.getAbsolutePath());
                }
            }
        }
    }

    static KeyStore createPkcs12KeyStore() {
        return createTrustStore(TruststoreFormat.PKCS12);
    }

    static KeyStore createGeneratedTrustStore() {
        return createTrustStore(getPreferredGeneratedTrustStoreType());
    }

    static KeyStore createTrustStore(TruststoreFormat truststoreType) {
        if (!truststoreType.isJavaTrustStore()) {
            throw new IllegalArgumentException(truststoreType.name() + " is not a Java KeyStore truststore format");
        }
        try {
            KeyStore truststore = CryptoIntegration.getProvider().getTrustStore(truststoreType);
            truststore.load(null, null);
            return truststore;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize truststore: cannot create a " + truststoreType + " keystore", e);
        }
    }

    static TruststoreFormat getPreferredGeneratedTrustStoreType() {
        return CryptoIntegration.getProvider().getPreferredGeneratedTrustStoreType();
    }

    /**
     * Include the default truststore, if it can be found.
     * <p>
     * The existing system properties will be preserved so that this logic can be rerun without consuming
     * the newly created merged truststore.
     */
    static void includeDefaultTruststore(KeyStore truststore) {
        String originalTruststoreKey = TruststoreBuilder.SYSTEM_TRUSTSTORE_KEY + ".orig";
        String originalTruststoreTypeKey = TruststoreBuilder.SYSTEM_TRUSTSTORE_TYPE_KEY + ".orig";
        String originalTruststorePasswordKey = TruststoreBuilder.SYSTEM_TRUSTSTORE_PASSWORD_KEY + ".orig";

        String trustStorePath = System.getProperty(originalTruststoreKey);
        String type = PKCS12;
        String password = null;
        File defaultTrustStore = null;
        if (trustStorePath == null) {
            trustStorePath = System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_KEY);
            if (trustStorePath == null) {
                defaultTrustStore = getJRETruststore();
                // Read the default JVM cacerts with its standard password rather than null: non-approved
                // BCFIPS (FIPS non-strict) throws "No password supplied for PKCS#12 KeyStore" on a null
                // password (reproduced in CI, issue #51680). Matches FileTruststoreProviderFactory, which
                // already defaults the cacerts password to "changeit".
                password = DEFAULT_CACERTS_PASSWORD;
                System.setProperty(originalTruststoreKey, defaultTrustStore.getAbsolutePath());
                System.setProperty(originalTruststoreTypeKey, type);
                System.setProperty(originalTruststorePasswordKey, password);
            } else {
                type = System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_TYPE_KEY, KeyStore.getDefaultType());
                password = System.getProperty(TruststoreBuilder.SYSTEM_TRUSTSTORE_PASSWORD_KEY);
                // save the original information
                System.setProperty(originalTruststoreKey, trustStorePath);
                System.setProperty(originalTruststoreTypeKey, type);
                if (password == null) {
                    System.getProperties().remove(originalTruststorePasswordKey);
                } else {
                    System.setProperty(originalTruststorePasswordKey, password);
                }
                defaultTrustStore = new File(trustStorePath);
            }
        } else {
            type = System.getProperty(originalTruststoreTypeKey);
            password = System.getProperty(originalTruststorePasswordKey);
            defaultTrustStore = new File(trustStorePath);
        }

        if (defaultTrustStore.exists()) {
            String path = defaultTrustStore.getAbsolutePath();
            mergeTrustStore(truststore, path, loadDefaultTruststore(path, type, password));
        } else {
            LOGGER.warnf("Default truststore was to be included, but could not be found at: %s", defaultTrustStore);
        }
    }

    /**
     * The default JVM cacerts is frequently JKS even when the default keystore type is PKCS12. SUN's PKCS12
     * reads a JKS file transparently (JDK compatibility mode) but BCFIPS does not, so under FIPS non-strict a
     * JKS cacerts otherwise fails as "stream does not represent a PKCS12 key store". Fall back to JKS (loaded
     * via the SUN provider), mirroring FileTruststoreProviderFactory. Reproduced and verified in CI (#51680).
     */
    private static KeyStore loadDefaultTruststore(String path, String type, String password) {
        try {
            return loadStore(path, type, password);
        } catch (RuntimeException primaryFailure) {
            if (!"jks".equalsIgnoreCase(type)) {
                try {
                    return loadStore(path, "jks", password);
                } catch (RuntimeException jksFailure) {
                    primaryFailure.addSuppressed(jksFailure);
                }
            }
            throw primaryFailure;
        }
    }

    /**
     * Load a PKCS12 truststore-paths source with a genuine empty-string password rather than a null one.
     * <p>
     * A null password makes SUN's PKCS12 implementation skip MAC verification and then silently drop the
     * (encrypted) certificate bags of an empty-password-MAC store - the entries vanish with NO exception, so
     * an exception-gated fallback never runs and those certs are lost from the merge (#51680, reproduced by
     * {@code SystemTruststoreChangeDetectionTest}/{@code TruststoreReloadTest} empty-MAC PKCS12 cases). An
     * empty string reads no-MAC, empty-password-MAC and - under non-approved BCFIPS, which rejects a null
     * PKCS12 password outright with "No password supplied for PKCS#12 KeyStore" - every supported PKCS12
     * truststore-paths shape (it is a strict superset of the null-password loader across SUN/BC/BCFIPS). Fall
     * back to a null password only if the empty string is rejected, preserving the previous behavior as a
     * safety net. Mirrors the {@link #loadDefaultTruststore} fallback structure.
     */
    private static KeyStore loadPkcs12Truststore(String path) {
        try {
            return loadStore(path, PKCS12, "");
        } catch (RuntimeException emptyPasswordFailure) {
            try {
                return loadStore(path, PKCS12, null);
            } catch (RuntimeException nullPasswordFailure) {
                emptyPasswordFailure.addSuppressed(nullPasswordFailure);
            }
            throw emptyPasswordFailure;
        }
    }

    static File getJRETruststore() {
        // try jre locations - there doesn't seem to be a good default mechanism for this
        String securityDirectory = System.getProperty("java.home") + File.separator + "lib" + File.separator
                + "security";
        File jssecacertsFile = new File(securityDirectory, "jssecacerts");
        if (jssecacertsFile.exists() && jssecacertsFile.isFile()) {
            return jssecacertsFile;
        }
        return new File(securityDirectory, "cacerts");
    }

    static KeyStore loadStore(String path, String type, String password) {
        try {
            return KeystoreUtil.loadKeyStore(path, password, type);
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize truststore: " + new File(path).getAbsolutePath() + ", type: " + type, e);
        }
    }

    static boolean mergePemFile(KeyStore truststore, String file, boolean isPem) {
        try (FileInputStream pemInputStream = new FileInputStream(file)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X509");
            boolean loadedAny = false;
            while (pemInputStream.available() > 0) {
                X509Certificate cert;
                try {
                    cert = (X509Certificate) certFactory.generateCertificate(pemInputStream);
                    loadedAny = true;
                } catch (CertificateException e) {
                    if (pemInputStream.available() > 0 || !loadedAny) {
                        // any remaining input means there is an actual problem with the key contents or
                        // file format
                        if (isPem || loadedAny) {
                            throw e;
                        }
                        LOGGER.debugf(e,
                                "The file %s may not be in PEM format, it will not be used to create the merged truststore",
                                new File(file).getAbsolutePath());
                        continue;
                    }
                    LOGGER.debugf(e,
                            "The trailing entry for %s generated a certificate exception, assuming instead that the file ends with comments",
                            new File(file).getAbsolutePath());
                    continue;
                }
                setCertificateEntry(truststore, cert);
            }
            return loadedAny;
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize truststore, could not merge: " + new File(file).getAbsolutePath(), e);
        }
    }

    private static void setCertificateEntry(KeyStore truststore, Certificate cert) throws KeyStoreException {
        String alias = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509Cert = (X509Certificate)cert;
            // use an alias that should be unique, yet deterministic
            alias = x509Cert.getSubjectX500Principal().getName() + "_" + x509Cert.getSerialNumber().toString(16);
        } else {
            // isn't expected
            alias = String.valueOf(Collections.list(truststore.aliases()).size());
        }
        truststore.setCertificateEntry(alias, cert);
    }

    private static void mergeTrustStore(KeyStore truststore, String file, KeyStore additionalStore) {
        try {
            for (String alias : Collections.list(additionalStore.aliases())) {
                if (additionalStore.isCertificateEntry(alias)) {
                    setCertificateEntry(truststore, additionalStore.getCertificate(alias));
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to initialize truststore, could not merge: " + new File(file).getAbsolutePath(), e);
        }
    }
}
