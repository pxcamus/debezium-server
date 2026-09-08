/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.SecretKeysHandler;
import io.smallrye.config.SecretKeysHandlerFactory;

/**
 * Builds the {@link VaultSecretKeysHandler} from {@code debezium.vault.<name>.*} configuration,
 * registered through {@code META-INF/services/io.smallrye.config.SecretKeysHandlerFactory}.
 * <p>
 * The factory form is used rather than registering the handler directly because it receives a
 * {@link ConfigSourceContext}: the addresses, paths and token locations are themselves ordinary
 * configuration, and the context resolves them before any secret expression is evaluated.
 * </p>
 * <p>
 * This sits alongside {@code DebeziumServerConfigSourceFactory}, which is registered the same way
 * and remaps {@code debezium.*} onto {@code quarkus.debezium.*}. Extending SmallRye configuration
 * from this module is an established pattern here, not a new one.
 * </p>
 *
 * <h2>Configuration</h2>
 *
 * <pre>
 * debezium.vault.names=prod-postgres
 * debezium.vault.prod-postgres.address=http://openbao.openbao.svc.cluster.local:8200
 * debezium.vault.prod-postgres.path=database/creds/pipeline
 * debezium.vault.prod-postgres.auth.role=pipeline
 * debezium.vault.prod-postgres.auth.token-path=/debezium/external/openbao-token/token
 * debezium.source.database.user=${vault::prod-postgres/username}
 * debezium.source.database.password=${vault::prod-postgres/password}
 * </pre>
 */
public class VaultSecretKeysHandlerFactory implements SecretKeysHandlerFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(VaultSecretKeysHandlerFactory.class);

    private static final String PREFIX = "debezium.vault.";
    private static final String NAMES = "debezium.vault.names";
    private static final String ADDRESS = "address";
    private static final String PATH = "path";
    private static final String AUTH_MOUNT = "auth.mount";
    private static final String AUTH_ROLE = "auth.role";
    private static final String AUTH_TOKEN_PATH = "auth.token-path";

    private static final String DEFAULT_AUTH_MOUNT = "kubernetes";
    private static final String DEFAULT_TOKEN_PATH = "/debezium/external/openbao-token/token";

    @Override
    public SecretKeysHandler getSecretKeysHandler(ConfigSourceContext context) {
        Map<String, Vault> vaults = new HashMap<>();

        for (String name : vaultNames(context)) {
            vaults.put(name, buildVault(context, name));
        }

        if (vaults.isEmpty()) {
            // Not an error. The handler is always registered because registration happens at build
            // time, while whether any vault exists is a deployment-time question. A configuration
            // with no vaults and no ${vault::...} expressions is perfectly normal.
            LOGGER.debug("No vaults configured; '{}' expressions will fail if any are used", VaultSecretKeysHandler.NAME);
        }
        else {
            LOGGER.info("Configured vault(s): {}", vaults.keySet());
        }

        return new VaultSecretKeysHandler(vaults);
    }

    /**
     * Determines which vaults are configured.
     * <p>
     * {@code debezium.vault.names} is authoritative when set, and it exists because discovery by
     * scanning property names does not survive environment variables. A variable is named
     * {@code DEBEZIUM_VAULT_PROD_POSTGRES_ADDRESS}, which maps back to
     * {@code debezium.vault.prod.postgres.address} — the vault name and the property beneath it
     * become indistinguishable. Looking a property up by name is unaffected, because SmallRye
     * converts in the other direction; only enumeration is lossy. Naming the vaults explicitly
     * sidesteps that, and matters here because a Debezium Server pod is configured by environment
     * variables whenever the operator is the one configuring it.
     * </p>
     */
    private static Set<String> vaultNames(ConfigSourceContext context) {
        ConfigValue declared = context.getValue(NAMES);

        if (declared != null && declared.getValue() != null && !declared.getValue().isBlank()) {
            Set<String> names = new HashSet<>();
            for (String name : declared.getValue().split(",")) {
                String trimmed = name.trim();
                if (!trimmed.isEmpty()) {
                    names.add(trimmed);
                }
            }
            return names;
        }

        return discoverVaultNames(context);
    }

    /**
     * Falls back to the distinct {@code <name>} segments in {@code debezium.vault.<name>.*}, for
     * configuration that comes from a properties file rather than the environment.
     */
    private static Set<String> discoverVaultNames(ConfigSourceContext context) {
        Set<String> names = new HashSet<>();

        for (Iterator<String> properties = context.iterateNames(); properties.hasNext();) {
            String property = properties.next();

            if (!property.startsWith(PREFIX) || property.equals(NAMES)) {
                continue;
            }

            String remainder = property.substring(PREFIX.length());
            int separator = remainder.indexOf('.');

            if (separator > 0) {
                names.add(remainder.substring(0, separator));
            }
        }

        return names;
    }

    private static Vault buildVault(ConfigSourceContext context, String name) {
        String address = required(context, name, ADDRESS);
        String path = required(context, name, PATH);
        String role = required(context, name, AUTH_ROLE);
        String mount = optional(context, name, AUTH_MOUNT, DEFAULT_AUTH_MOUNT);
        String tokenPath = optional(context, name, AUTH_TOKEN_PATH, DEFAULT_TOKEN_PATH);

        SecretStore store = new OpenBaoSecretStore(address, mount, role, Path.of(tokenPath));
        return new Vault(name, path, store);
    }

    private static String required(ConfigSourceContext context, String vault, String key) {
        String value = value(context, vault, key);

        if (value == null || value.isBlank()) {
            throw new VaultException("Vault '" + vault + "' is missing the required property "
                    + PREFIX + vault + "." + key);
        }

        return value;
    }

    private static String optional(ConfigSourceContext context, String vault, String key, String fallback) {
        String value = value(context, vault, key);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String value(ConfigSourceContext context, String vault, String key) {
        ConfigValue configValue = context.getValue(PREFIX + vault + "." + key);
        return configValue == null ? null : configValue.getValue();
    }

    @Override
    public String getName() {
        return VaultSecretKeysHandler.NAME;
    }
}
