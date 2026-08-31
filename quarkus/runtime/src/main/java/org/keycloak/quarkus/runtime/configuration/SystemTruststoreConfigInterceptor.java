package org.keycloak.quarkus.runtime.configuration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import jakarta.annotation.Priority;

import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.common.util.KeystoreUtil.TruststoreFormat;
import org.keycloak.config.TruststoreOptions;
import org.keycloak.truststore.SystemTruststoreReload;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.Priorities;

import static org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX;

@Priority(Priorities.APPLICATION - 5)
public class SystemTruststoreConfigInterceptor implements ConfigSourceInterceptor {

    private static final String PREFIX = "quarkus.tls.\"" + SystemTruststoreReload.TLS_BUCKET_PREFIX;
    private static final String PKCS12_BUCKET_SUFFIX = "-pkcs12-";
    private static final String PEM_CERTS = "trust-store.pem.certs";
    private static final String PKCS12_PATH = "trust-store.p12.path";
    private static final String RELOAD_PERIOD = "reload-period";
    private static final String PATHS = NS_KEYCLOAK_PREFIX + TruststoreOptions.TRUSTSTORE_PATHS.getKey();
    private static final String RELOAD = NS_KEYCLOAK_PREFIX + TruststoreOptions.TRUSTSTORE_PATHS_RELOAD_PERIOD.getKey();

    @Override
    public ConfigValue getValue(ConfigSourceInterceptorContext context, String name) {
        if (name.startsWith(PREFIX)) {
            String value = resolve(context, name);
            if (value != null) {
                return ConfigValue.builder().withName(name).withValue(value).build();
            }
        }
        return context.proceed(name);
    }

    @Override
    public Iterator<String> iterateNames(ConfigSourceInterceptorContext context) {
        Set<String> names = new LinkedHashSet<>();
        context.iterateNames().forEachRemaining(names::add);
        Buckets buckets = buckets(context);
        boolean reload = readValue(context, RELOAD) != null;
        if (!buckets.pem.isEmpty()) {
            names.add(key("", PEM_CERTS));
            if (reload) {
                names.add(key("", RELOAD_PERIOD));
            }
        }
        for (int index = 0; index < buckets.pkcs12.size(); index++) {
            names.add(key(PKCS12_BUCKET_SUFFIX + index, PKCS12_PATH));
            if (reload) {
                names.add(key(PKCS12_BUCKET_SUFFIX + index, RELOAD_PERIOD));
            }
        }
        return names.iterator();
    }

    private String resolve(ConfigSourceInterceptorContext context, String name) {
        String rest = name.substring(PREFIX.length());
        int separator = rest.indexOf("\".");
        if (separator < 0) {
            return null;
        }
        String suffix = rest.substring(0, separator);
        String leaf = rest.substring(separator + 2);
        Buckets buckets = buckets(context);

        if (suffix.isEmpty()) {
            if (buckets.pem.isEmpty()) {
                return null;
            }
            if (PEM_CERTS.equals(leaf)) {
                return String.join(",", buckets.pem);
            }
            if (RELOAD_PERIOD.equals(leaf)) {
                return readValue(context, RELOAD);
            }
            return null;
        }

        if (suffix.startsWith(PKCS12_BUCKET_SUFFIX)) {
            int index;
            try {
                index = Integer.parseInt(suffix.substring(PKCS12_BUCKET_SUFFIX.length()));
            } catch (NumberFormatException e) {
                return null;
            }
            if (index < 0 || index >= buckets.pkcs12.size()) {
                return null;
            }
            if (PKCS12_PATH.equals(leaf)) {
                return buckets.pkcs12.get(index);
            }
            if (RELOAD_PERIOD.equals(leaf)) {
                return readValue(context, RELOAD);
            }
        }
        return null;
    }

    private Buckets buckets(ConfigSourceInterceptorContext context) {
        Buckets buckets = new Buckets();
        String paths = readValue(context, PATHS);
        if (paths == null || paths.isBlank()) {
            return buckets;
        }
        for (String entry : paths.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            File file = new File(trimmed);
            if (file.isDirectory()) {
                List<File> found = new ArrayList<>();
                collect(file, found, new HashSet<>());
                found.sort(Comparator.comparing(File::getAbsolutePath));
                for (File child : found) {
                    classify(child.getAbsolutePath(), buckets);
                }
            } else {
                classify(trimmed, buckets);
            }
        }
        return buckets;
    }

    private static void classify(String path, Buckets buckets) {
        KeystoreUtil.getTruststoreFormat(path).ifPresent(format -> {
            if (format == TruststoreFormat.PEM) {
                buckets.pem.add(path);
            } else if (format == TruststoreFormat.PKCS12) {
                buckets.pkcs12.add(path);
            }
        });
    }

    private static void collect(File directory, List<File> found, Set<String> visited) {
        String canonical;
        try {
            canonical = directory.getCanonicalPath();
        } catch (IOException e) {
            return;
        }
        if (!visited.add(canonical)) {
            return;
        }
        File[] children = directory.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                collect(child, found, visited);
            } else {
                found.add(child);
            }
        }
    }

    private static String readValue(ConfigSourceInterceptorContext context, String name) {
        ConfigValue value = context.proceed(name);
        return value == null ? null : value.getValue();
    }

    private static String key(String suffix, String leaf) {
        return PREFIX + suffix + "\"." + leaf;
    }

    private static final class Buckets {
        private final List<String> pem = new ArrayList<>();
        private final List<String> pkcs12 = new ArrayList<>();
    }
}
