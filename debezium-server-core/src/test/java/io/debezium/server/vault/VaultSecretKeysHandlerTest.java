/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link VaultSecretKeysHandler}.
 */
public class VaultSecretKeysHandlerTest {

    private FakeSecretStore store;
    private VaultSecretKeysHandler handler;

    @BeforeEach
    public void setUp() {
        store = new FakeSecretStore(Map.of("username", "dbz", "password", "s3cret"));
        handler = new VaultSecretKeysHandler(Map.of("db", new Vault("db", "any/path", store)));
    }

    @Test
    public void shouldDecodeValuesFromTheNamedVault() {
        assertThat(handler.decode("db/password")).isEqualTo("s3cret");
        assertThat(handler.decode("db/username")).isEqualTo("dbz");
    }

    @Test
    public void shouldReadTheStoreOnlyOncePerVault() {
        handler.decode("db/username");
        handler.decode("db/password");

        assertThat(store.readCount()).isEqualTo(1);
    }

    @Test
    public void shouldFailOnUnknownVaultNamingTheKnownOnes() {
        assertThatThrownBy(() -> handler.decode("nope/password"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("No vault named 'nope'")
                .hasMessageContaining("Known vaults")
                .hasMessageContaining("db");
    }

    @Test
    public void shouldFailOnUnknownKeyNamingTheAvailableOnes() {
        assertThatThrownBy(() -> handler.decode("db/nope"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Vault 'db' has no key 'nope'")
                .hasMessageContaining("Available keys")
                .hasMessageContaining("username")
                .hasMessageContaining("password");
    }

    @Test
    public void shouldNotCacheAFailedRead() {
        store.failWith(new VaultException("store is down"));

        assertThatThrownBy(() -> handler.decode("db/password"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("store is down");
        assertThatThrownBy(() -> handler.decode("db/password"))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("store is down");
        assertThat(store.readCount()).isEqualTo(2);
    }

    @Test
    public void shouldBeNamedVault() {
        assertThat(handler.getName()).isEqualTo("vault");
    }

    /**
     * A {@link SecretStore} that serves a fixed map and counts how often it was read.
     */
    private static final class FakeSecretStore implements SecretStore {

        private final Map<String, String> values;
        private final AtomicInteger readCount = new AtomicInteger();
        private RuntimeException failure;

        private FakeSecretStore(Map<String, String> values) {
            this.values = values;
        }

        @Override
        public Map<String, String> read(String path) {
            readCount.incrementAndGet();
            if (failure != null) {
                throw failure;
            }
            return values;
        }

        int readCount() {
            return readCount.get();
        }

        void failWith(RuntimeException failure) {
            this.failure = failure;
        }
    }
}
