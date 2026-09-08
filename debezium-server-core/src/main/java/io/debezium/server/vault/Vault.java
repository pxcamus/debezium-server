/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import java.util.Map;

/**
 * A named secret store together with the single path a pipeline reads from it.
 * <p>
 * Naming the vault, rather than writing its address and path into every property, is what keeps
 * "where secrets live" an administrative decision and "which secret do I want" a pipeline one. It
 * also means a reference cannot be used to read an arbitrary path: the path is fixed by whoever
 * defined the vault.
 * </p>
 */
public final class Vault {

    private final String name;
    private final String path;
    private final SecretStore store;

    public Vault(String name, String path, SecretStore store) {
        this.name = name;
        this.path = path;
        this.store = store;
    }

    public String name() {
        return name;
    }

    Map<String, String> read() {
        return store.read(path);
    }

    void close() {
        try {
            store.close();
        }
        catch (Exception e) {
            throw new VaultException("Failed to close the store behind vault '" + name + "'.", e);
        }
    }
}
