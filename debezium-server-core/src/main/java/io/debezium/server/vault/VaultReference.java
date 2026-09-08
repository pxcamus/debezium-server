/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

/**
 * The right-hand side of a {@code ${vault::<name>/<key>}} configuration expression.
 *
 * @param vaultName the vault to read, as named in {@code debezium.vault.<name>.*}
 * @param key which value from that vault, e.g. {@code username} or {@code password}
 */
public record VaultReference(String vaultName, String key) {

    private static final char SEPARATOR = '/';

    public static VaultReference parse(String reference) {
        int separator = reference.indexOf(SEPARATOR);

        if (separator < 1 || separator == reference.length() - 1) {
            throw new VaultException("Malformed vault reference '" + reference
                    + "'. Expected <vault-name>" + SEPARATOR + "<key>, for example 'prod-postgres"
                    + SEPARATOR + "password'.");
        }

        return new VaultReference(reference.substring(0, separator), reference.substring(separator + 1));
    }

    @Override
    public String toString() {
        return vaultName + SEPARATOR + key;
    }
}
