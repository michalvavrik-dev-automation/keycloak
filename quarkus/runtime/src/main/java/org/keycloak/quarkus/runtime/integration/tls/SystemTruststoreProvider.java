package org.keycloak.quarkus.runtime.integration.tls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.TrustManagerFactory;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.logging.Logger;
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

    private static final Logger LOGGER = Logger.getLogger(SystemTruststoreProvider.class);

    @Override
    public TrustStoreAndTrustOptions getTrustStore(Vertx vertx) {
        KeyStore ks = TruststoreBuilder.getSystemTruststore();
        if (ks == null) {
            // Diagnostic (#51680): a null result here at bucket construction (RUNTIME_INIT) leaves the TLS
            // holder with a null trustStore, so VertxCertificateHolder.reload() returns false forever and the
            // reload-period timer never fires a CertificateUpdatedEvent - i.e. the whole reload chain is inert.
            LOGGER.info("[truststore-reload] provider returning null: system truststore not built (inert bucket)");
            return null;
        }
        LOGGER.debugf("[truststore-reload] provider returning system truststore (%d entries)", trustStoreSize(ks));
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            return new TrustStoreAndTrustOptions(ks, TrustOptions.wrap(tmf));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static int trustStoreSize(KeyStore ks) {
        try {
            return ks.size();
        } catch (Exception e) {
            return -1;
        }
    }
}
