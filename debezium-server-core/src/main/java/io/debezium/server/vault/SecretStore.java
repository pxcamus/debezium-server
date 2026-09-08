/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import java.util.Map;

/**
 * Reads a set of secret values from an external store.
 * <p>
 * There is one implementation per <em>secret store</em> — OpenBao, HashiCorp Vault, AWS Secrets
 * Manager, Azure Key Vault — and never one per connector. That distinction is the reason this
 * interface exists at all: resolution happens on configuration properties, which are indifferent
 * to whether the value being filled in is a database password, a connection string, a bearer
 * token for an HTTP sink, or the credentials for the schema history and offset storage backends.
 * Adding a store is a new implementation here; adding a connector is nothing at all.
 * </p>
 */
public interface SecretStore extends AutoCloseable {

    /**
     * Reads every value held at {@code path}.
     * <p>
     * Returning the whole set rather than a single key lets a caller resolve several properties
     * from one read — a dynamic database credential arrives as a username and a password together,
     * and fetching them separately would mint two unrelated credentials.
     * </p>
     *
     * @param path store-specific location, e.g. {@code database/creds/pipeline}
     * @return the values at that path, never {@code null}
     * @throws VaultException if the store cannot be reached or refuses the request
     */
    Map<String, String> read(String path);

    @Override
    default void close() {
    }
}
