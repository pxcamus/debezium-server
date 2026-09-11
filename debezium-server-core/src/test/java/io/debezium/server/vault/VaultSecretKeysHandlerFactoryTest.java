/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.SecretKeysHandler;

/**
 * Unit tests for {@link VaultSecretKeysHandlerFactory}.
 */
public class VaultSecretKeysHandlerFactoryTest {

    private static final String KNOWN_VAULTS_MARKER = "Known vaults: [";

    private final VaultSecretKeysHandlerFactory factory = new VaultSecretKeysHandlerFactory();

    @Test
    public void shouldBuildEveryVaultListedInNames() {
        SecretKeysHandler handler = factory.getSecretKeysHandler(context(Map.of(
                "debezium.vault.names", "a, b",
                "debezium.vault.a.address", "http://unreachable.invalid:1",
                "debezium.vault.a.path", "a/path",
                "debezium.vault.a.auth.role", "a-role",
                "debezium.vault.b.address", "http://unreachable.invalid:1",
                "debezium.vault.b.path", "b/path",
                "debezium.vault.b.auth.role", "b-role")));

        assertThatThrownBy(() -> handler.decode("c/x"))
                .isInstanceOf(VaultException.class)
                .satisfies(e -> assertThat(knownVaults(e.getMessage())).containsExactlyInAnyOrder("a", "b"));
    }

    @Test
    public void shouldDiscoverVaultsFromPropertyNamesWhenNamesIsUnset() {
        SecretKeysHandler handler = factory.getSecretKeysHandler(context(Map.of(
                "debezium.vault.a.address", "http://unreachable.invalid:1",
                "debezium.vault.a.path", "a/path",
                "debezium.vault.a.auth.role", "a-role")));

        assertThatThrownBy(() -> handler.decode("c/x"))
                .isInstanceOf(VaultException.class)
                .satisfies(e -> assertThat(knownVaults(e.getMessage())).containsExactly("a"));
    }

    @Test
    public void shouldNotDiscoverVaultsOutsideTheDeclaredNames() {
        SecretKeysHandler handler = factory.getSecretKeysHandler(context(Map.of(
                "debezium.vault.names", "a",
                "debezium.vault.a.address", "http://unreachable.invalid:1",
                "debezium.vault.a.path", "a/path",
                "debezium.vault.a.auth.role", "a-role",
                "debezium.vault.z.address", "http://unreachable.invalid:1",
                "debezium.vault.z.path", "z/path",
                "debezium.vault.z.auth.role", "z-role")));

        assertThatThrownBy(() -> handler.decode("z/x"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("No vault named 'z'")
                .satisfies(e -> assertThat(knownVaults(e.getMessage())).containsExactly("a"));
    }

    @Test
    public void shouldFailWhenANamedVaultHasNoAddress() {
        assertThatThrownBy(() -> factory.getSecretKeysHandler(context(Map.of(
                "debezium.vault.names", "a",
                "debezium.vault.a.path", "a/path",
                "debezium.vault.a.auth.role", "a-role"))))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("debezium.vault.a.address");
    }

    /**
     * Extracts the names from the {@code Known vaults: [...]} tail of a handler error message.
     */
    private static List<String> knownVaults(String message) {
        int start = message.indexOf(KNOWN_VAULTS_MARKER);
        int end = message.lastIndexOf(']');
        if (start < 0 || end < start) {
            return List.of();
        }
        String inside = message.substring(start + KNOWN_VAULTS_MARKER.length(), end).trim();
        return inside.isEmpty() ? List.of() : List.of(inside.split(", "));
    }

    private static ConfigSourceContext context(Map<String, String> properties) {
        return new MapConfigSourceContext(properties);
    }

    /**
     * Minimal {@link ConfigSourceContext} backed by a fixed map, so the factory can be exercised
     * without the full MicroProfile Config runtime.
     */
    private static final class MapConfigSourceContext implements ConfigSourceContext {

        private final Map<String, String> properties;

        MapConfigSourceContext(Map<String, String> properties) {
            this.properties = properties;
        }

        @Override
        public ConfigValue getValue(String name) {
            String value = properties.get(name);
            return value == null ? null : ConfigValue.builder().withName(name).withValue(value).build();
        }

        @Override
        public Iterator<String> iterateNames() {
            return properties.keySet().iterator();
        }
    }
}
