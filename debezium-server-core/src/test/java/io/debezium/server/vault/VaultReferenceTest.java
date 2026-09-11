/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link VaultReference}.
 */
public class VaultReferenceTest {

    @Test
    public void shouldParseNameAndKey() {
        VaultReference reference = VaultReference.parse("name/key");

        assertThat(reference.vaultName()).isEqualTo("name");
        assertThat(reference.key()).isEqualTo("key");
        assertThat(reference).hasToString("name/key");
    }

    @Test
    public void shouldSplitOnFirstSlashOnly() {
        VaultReference reference = VaultReference.parse("a/b/c");

        assertThat(reference.vaultName()).isEqualTo("a");
        assertThat(reference.key()).isEqualTo("b/c");
        assertThat(reference).hasToString("a/b/c");
    }

    @ParameterizedTest
    @ValueSource(strings = { "nokey", "/key", "name/", "/" })
    public void shouldRejectMalformedReferences(String malformed) {
        assertThatThrownBy(() -> VaultReference.parse(malformed))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("'" + malformed + "'");
    }

    @Test
    public void shouldRejectEmptyReference() {
        assertThatThrownBy(() -> VaultReference.parse(""))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("''");
    }
}
