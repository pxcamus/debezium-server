/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.smallrye.config.SecretKeysHandler;

/**
 * Resolves {@code ${vault::<vault-name>/<key>}} expressions in Debezium Server configuration
 * against an external secret store, so that a credential never has to be written into the
 * configuration itself.
 * <p>
 * The handler operates on configuration properties rather than inside any one connector, which is
 * the point: it is indifferent to whether the property it fills in is a database password, a
 * connection string, a bearer token for an HTTP sink, or the credentials for the schema history
 * and offset storage backends. Those last two belong to neither source nor sink, so a mechanism
 * attached to a connector would miss them structurally.
 * </p>
 */
public class VaultSecretKeysHandler implements SecretKeysHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultSecretKeysHandler.class);

    /**
     * The name that appears before {@code ::} in a configuration expression.
     */
    public static final String NAME = "vault";

    private final Map<String, Vault> vaults;

    /**
     * One entry per vault, not per expression.
     * <p>
     * SmallRye re-evaluates an expression on every read — a single property was observed resolving
     * four times during startup — and a dynamic credential is minted fresh by the store on each
     * read. Without this, one pipeline would mint a new database role per property per read and
     * orphan all but the last. Caching the whole response also keeps a username and the password
     * that belongs to it together, which fetching them separately would not.
     * </p>
     */
    private final Map<String, Map<String, String>> resolved = new ConcurrentHashMap<>();

    public VaultSecretKeysHandler(Map<String, Vault> vaults) {
        this.vaults = vaults;
    }

    @Override
    public String decode(String secret) {
        VaultReference reference = VaultReference.parse(secret);

        Vault vault = vaults.get(reference.vaultName());
        if (vault == null) {
            throw new VaultException("No vault named '" + reference.vaultName() + "' is configured. "
                    + "Define it with debezium.vault." + reference.vaultName() + ".* properties. "
                    + "Known vaults: " + vaults.keySet());
        }

        Map<String, String> values = resolved.computeIfAbsent(reference.vaultName(), name -> {
            LOGGER.info("Resolving vault '{}' for the first time", name);
            return vault.read();
        });

        String value = values.get(reference.key());
        if (value == null) {
            throw new VaultException("Vault '" + reference.vaultName() + "' has no key '" + reference.key()
                    + "'. Available keys: " + values.keySet());
        }

        return value;
    }

    @Override
    public String getName() {
        return NAME;
    }
}
