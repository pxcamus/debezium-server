/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * A {@link SecretStore} backed by OpenBao (or HashiCorp Vault, whose HTTP API this matches),
 * authenticating with the pod's own Kubernetes ServiceAccount token.
 * <p>
 * Nothing injects the store token. The pod presents an audience-scoped ServiceAccount token that
 * the kubelet mounted, OpenBao verifies it with the Kubernetes API's TokenReview endpoint, and the
 * store token comes back as the response to that call. The audience is what contains the blast
 * radius: a token stamped for the secret store cannot be replayed against the Kubernetes API
 * server.
 * </p>
 */
public class OpenBaoSecretStore implements SecretStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenBaoSecretStore.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
    private static final String TOKEN_HEADER = "X-Vault-Token";

    private final String address;
    private final String authMount;
    private final String authRole;
    private final Path serviceAccountTokenPath;
    private final HttpClient httpClient;

    private volatile String storeToken;

    public OpenBaoSecretStore(String address, String authMount, String authRole, Path serviceAccountTokenPath) {
        this.address = stripTrailingSlash(address);
        this.authMount = authMount;
        this.authRole = authRole;
        this.serviceAccountTokenPath = serviceAccountTokenPath;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
    }

    @Override
    public Map<String, String> read(String path) {
        JsonNode response = get("/v1/" + stripLeadingSlash(path), login());
        JsonNode data = response.path("data");

        if (data.isMissingNode() || !data.isObject()) {
            throw new VaultException("No data at '" + path + "'. The path exists but returned nothing readable, "
                    + "which usually means it is a KV v2 mount and needs the 'data/' segment.");
        }

        // KV v2 is versioned, so it wraps the payload one level deeper: the values sit under
        // data.data with the version bookkeeping beside them under data.metadata. No other engine
        // produces that pair, so the shape is detected rather than configured.
        if (data.path("data").isObject() && data.has("metadata")) {
            data = data.get("data");
        }

        Map<String, String> values = new LinkedHashMap<>();
        data.fields().forEachRemaining(field -> {
            if (field.getValue().isValueNode()) {
                values.put(field.getKey(), field.getValue().asText());
            }
        });

        if (values.isEmpty()) {
            throw new VaultException("Read no values from '" + path + "'. The path answered but contained "
                    + "nothing usable as a secret value.");
        }

        // Deliberately logs the keys and not the values. Knowing which keys came back is what makes
        // a mistyped reference diagnosable; the values are the thing this class exists to protect.
        LOGGER.info("Read {} value(s) from '{}': {}", values.size(), path, values.keySet());
        return values;
    }

    /**
     * Exchanges the pod's ServiceAccount token for a store token, once per instance.
     */
    private String login() {
        String cached = storeToken;
        if (cached != null) {
            return cached;
        }

        synchronized (this) {
            if (storeToken != null) {
                return storeToken;
            }

            String serviceAccountToken = readServiceAccountToken();

            ObjectNode body = MAPPER.createObjectNode()
                    .put("role", authRole)
                    .put("jwt", serviceAccountToken);

            JsonNode response = post("/v1/auth/" + authMount + "/login", body.toString());
            JsonNode auth = response.path("auth");
            String token = auth.path("client_token").asText(null);

            if (token == null || token.isBlank()) {
                throw new VaultException("Login to " + address + " as role '" + authRole + "' returned no client_token.");
            }

            LOGGER.info("Authenticated to {} as role '{}'; lease {}s, renewable={}",
                    address, authRole, auth.path("lease_duration").asLong(), auth.path("renewable").asBoolean());

            storeToken = token;
            return token;
        }
    }

    private String readServiceAccountToken() {
        try {
            String token = Files.readString(serviceAccountTokenPath, StandardCharsets.UTF_8).trim();
            if (token.isEmpty()) {
                throw new VaultException("The ServiceAccount token at " + serviceAccountTokenPath + " is empty.");
            }
            return token;
        }
        catch (IOException e) {
            throw new VaultException("Cannot read the ServiceAccount token at " + serviceAccountTokenPath
                    + ". The pod must mount a projected token whose audience matches the one the store's "
                    + "Kubernetes auth role is bound to.", e);
        }
    }

    private JsonNode post(String path, String body) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(address + path))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        return send(request, path);
    }

    private JsonNode get(String path, String token) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(address + path))
                .timeout(REQUEST_TIMEOUT)
                .header(TOKEN_HEADER, token)
                .GET()
                .build();
        return send(request, path);
    }

    private JsonNode send(HttpRequest request, String path) {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() / 100 != 2) {
                // The body carries the store's own "errors" array, which names the missing capability
                // on a 403 — far more useful than the status code alone.
                throw new VaultException("Request to " + path + " failed with HTTP " + response.statusCode()
                        + ": " + response.body());
            }

            return MAPPER.readTree(response.body());
        }
        catch (IOException e) {
            throw new VaultException("Request to " + address + path + " failed.", e);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VaultException("Interrupted while calling " + address + path + ".", e);
        }
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String stripLeadingSlash(String value) {
        return value.startsWith("/") ? value.substring(1) : value;
    }
}
