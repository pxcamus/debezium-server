/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import io.debezium.DebeziumException;

/**
 * Raised when a secret cannot be resolved.
 * <p>
 * Always fatal, and deliberately so: the alternative to failing here is starting a connector with
 * an unresolved or empty credential, which surfaces much later as an authentication error against
 * the source database and reads as a configuration mistake rather than a secret-store problem.
 * </p>
 */
public class VaultException extends DebeziumException {

    private static final long serialVersionUID = 1L;

    public VaultException(String message) {
        super(message);
    }

    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
