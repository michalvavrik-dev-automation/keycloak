package org.keycloak.quarkus.runtime.integration.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.TrustManagerFactory;

import jakarta.enterprise.context.ApplicationScoped;

import org.keycloak.truststore.SystemTruststoreReload;
import org.keycloak.truststore.TruststoreBuilder;

import io.quarkus.tls.TrustStoreAndTrustOptions;
import io.quarkus.tls.TrustStoreProvider;
import io.smallrye.common.annotation.Identifier;
import io.vertx.core.Vertx;
import io.vertx.core.net.TrustOptions;

@ApplicationScoped
@Identifier(SystemTruststoreReload.TLS_BUCKET_PREFIX)
public class SystemTruststoreProvider implements TrustStoreProvider {

    @Override
    public TrustStoreAndTrustOptions getTrustStore(Vertx vertx) {
        KeyStore ks = TruststoreBuilder.getSystemTruststore();
        if (ks == null) {
            return null;
        }
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            return new TrustStoreAndTrustOptions(ks, TrustOptions.wrap(tmf));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
