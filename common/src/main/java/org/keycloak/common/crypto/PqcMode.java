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

package org.keycloak.common.crypto;

/**
 * Post-quantum cryptography (PQC) modes.
 * <p>
 * A mode expresses how strictly PQC algorithms are required in a particular area of the server, for example the TLS key
 * exchange of incoming HTTPS connections. Each area that supports PQC exposes its own configuration option of this type
 * because the areas are expected to be migrated to PQC one by one.
 */
public enum PqcMode {

    /**
     * PQC algorithms are used when both the server and the peer support and negotiate them. Algorithms that are not
     * considered post-quantum safe remain available as a fallback.
     */
    OPTIONAL("optional"),

    /**
     * Only hybrid PQC algorithms, which combine a classical algorithm with a post-quantum one, are made available.
     * Peers that do not support any of them are rejected.
     */
    ENFORCE_HYBRID("enforce-hybrid");

    private final String optionName;

    PqcMode(String optionName) {
        this.optionName = optionName;
    }

    public static PqcMode valueOfOption(String name) {
        return valueOf(name.toUpperCase().replace('-', '_'));
    }

    @Override
    public String toString() {
        return optionName;
    }
}
