/*
 * Copyright Debezium Authors.
 *
 * Licensed under the Apache Software License version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0
 */
package io.debezium.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

/**
 * Unit tests for {@link OpenBaoSecretStore} against a stub of the OpenBao HTTP API.
 */
public class OpenBaoSecretStoreTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String SERVICE_ACCOUNT_TOKEN = "sa-token";
    private static final String STORE_TOKEN = "tok";
    private static final String ROLE = "pipeline";
    private static final String AUTH_MOUNT = "kubernetes";
    private static final String VAULT_PATH = "db/creds/pipeline";
    private static final String LOGIN_PATH = "/v1/auth/kubernetes/login";
    private static final String READ_PATH = "/v1/" + VAULT_PATH;
    private static final String LOGIN_RESPONSE = "{\"auth\":{\"client_token\":\"" + STORE_TOKEN
            + "\",\"lease_duration\":3600,\"renewable\":true}}";

    @TempDir
    Path tempDir;

    private HttpServer server;
    private String address;
    private Path tokenFile;
    private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();

    @BeforeEach
    public void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        address = "http://127.0.0.1:" + server.getAddress().getPort();
        tokenFile = tempDir.resolve("token");
        Files.writeString(tokenFile, SERVICE_ACCOUNT_TOKEN);
    }

    @AfterEach
    public void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    public void shouldLoginThenReadThePath() throws IOException {
        stubLoginAndRead("{\"data\":{\"username\":\"u\",\"password\":\"p\"}}");

        Map<String, String> values = newStore().read(VAULT_PATH);

        assertThat(values).containsExactly(entry("username", "u"), entry("password", "p"));

        RecordedRequest login = onlyRequestTo(LOGIN_PATH);
        assertThat(login.method()).isEqualTo("POST");
        JsonNode loginBody = MAPPER.readTree(login.body());
        assertThat(loginBody.path("role").asText()).isEqualTo(ROLE);
        assertThat(loginBody.path("jwt").asText()).isEqualTo(SERVICE_ACCOUNT_TOKEN);

        RecordedRequest read = onlyRequestTo(READ_PATH);
        assertThat(read.method()).isEqualTo("GET");
        assertThat(read.header("X-Vault-Token")).isEqualTo(STORE_TOKEN);
    }

    @Test
    public void shouldLoginOnlyOncePerStoreInstance() {
        stubLoginAndRead("{\"data\":{\"password\":\"p\"}}");

        OpenBaoSecretStore store = newStore();
        store.read(VAULT_PATH);
        store.read(VAULT_PATH);

        assertThat(requestsTo(LOGIN_PATH)).hasSize(1);
        assertThat(requestsTo(READ_PATH)).hasSize(2);
    }

    @Test
    public void shouldUseTheConfiguredAuthMount() {
        stubJson("/v1/auth/k8s-prod/login", LOGIN_RESPONSE);
        stubJson(READ_PATH, "{\"data\":{\"password\":\"p\"}}");

        OpenBaoSecretStore store = new OpenBaoSecretStore(address, "k8s-prod", ROLE, tokenFile);

        assertThat(store.read(VAULT_PATH)).containsEntry("password", "p");
        assertThat(requestsTo("/v1/auth/k8s-prod/login")).hasSize(1);
    }

    @Test
    public void shouldTolerateTrailingSlashOnAddressAndLeadingSlashOnPath() {
        stubLoginAndRead("{\"data\":{\"password\":\"p\"}}");

        OpenBaoSecretStore store = new OpenBaoSecretStore(address + "/", AUTH_MOUNT, ROLE, tokenFile);

        assertThat(store.read("/" + VAULT_PATH)).containsEntry("password", "p");
        onlyRequestTo(READ_PATH);
    }

    @Test
    public void shouldUnwrapKvV2Payload() {
        stubLoginAndRead("{\"data\":{\"data\":{\"password\":\"p\"},\"metadata\":{\"version\":3}}}");

        assertThat(newStore().read(VAULT_PATH)).containsExactly(entry("password", "p"));
    }

    @Test
    public void shouldKeepOnlyScalarValuesFromAFlatPayload() {
        stubLoginAndRead("{\"data\":{\"a\":\"1\",\"nested\":{\"x\":\"y\"},\"list\":[1]}}");

        assertThat(newStore().read(VAULT_PATH)).containsExactly(entry("a", "1"));
    }

    @Test
    public void shouldRenderNumbersAndBooleansAsStrings() {
        stubLoginAndRead("{\"data\":{\"port\":5432,\"ssl\":true}}");

        assertThat(newStore().read(VAULT_PATH)).containsExactly(entry("port", "5432"), entry("ssl", "true"));
    }

    @Test
    public void shouldSkipNullValues() {
        stubLoginAndRead("{\"data\":{\"a\":null,\"b\":\"x\"}}");

        assertThat(newStore().read(VAULT_PATH)).containsExactly(entry("b", "x"));
    }

    @Test
    public void shouldFailWhenThereIsNoDataObject() {
        stubLoginAndRead("{}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(VAULT_PATH);
    }

    @Test
    public void shouldFailWhenDataIsNotAnObject() {
        stubLoginAndRead("{\"data\":\"text\"}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(VAULT_PATH);
    }

    @Test
    public void shouldFailWhenDataIsEmpty() {
        stubLoginAndRead("{\"data\":{}}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Read no values");
    }

    @Test
    public void shouldFailWhenDataHasOnlyNonScalarValues() {
        stubLoginAndRead("{\"data\":{\"nested\":{\"x\":\"y\"},\"list\":[1]}}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("Read no values");
    }

    @Test
    public void shouldFailWithStatusAndStoreErrorsOnHttpError() {
        stubJson(LOGIN_PATH, LOGIN_RESPONSE);
        stub(READ_PATH, 403, "{\"errors\":[\"permission denied\"]}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("403")
                .hasMessageContaining("permission denied");
    }

    @Test
    public void shouldFailWhenLoginReturnsNoClientToken() {
        stubJson(LOGIN_PATH, "{\"auth\":{}}");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(ROLE)
                .hasMessageContaining("client_token");
    }

    @Test
    public void shouldFailWhenTheTokenFileIsMissing() {
        Path missing = tempDir.resolve("missing-token");
        OpenBaoSecretStore store = new OpenBaoSecretStore(address, AUTH_MOUNT, ROLE, missing);

        assertThatThrownBy(() -> store.read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining(missing.toString())
                .hasCauseInstanceOf(IOException.class);
    }

    @Test
    public void shouldFailWhenTheTokenFileIsEmpty() throws IOException {
        Files.writeString(tokenFile, "  \n");

        assertThatThrownBy(() -> newStore().read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasMessageContaining("empty");
    }

    @Test
    public void shouldFailWhenTheStoreIsUnreachable() {
        int port = server.getAddress().getPort();
        server.stop(0);
        server = null;
        OpenBaoSecretStore store = new OpenBaoSecretStore("http://127.0.0.1:" + port, AUTH_MOUNT, ROLE, tokenFile);

        assertThatThrownBy(() -> store.read(VAULT_PATH))
                .isInstanceOf(VaultException.class)
                .hasCauseInstanceOf(IOException.class);
    }

    private OpenBaoSecretStore newStore() {
        return new OpenBaoSecretStore(address, AUTH_MOUNT, ROLE, tokenFile);
    }

    private void stubLoginAndRead(String readResponse) {
        stubJson(LOGIN_PATH, LOGIN_RESPONSE);
        stubJson(READ_PATH, readResponse);
    }

    private void stubJson(String path, String body) {
        stub(path, 200, body);
    }

    private void stub(String path, int status, String body) {
        server.createContext(path, exchange -> {
            requests.add(new RecordedRequest(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    new LinkedHashMap<>(exchange.getRequestHeaders()),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            byte[] responseBody = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, responseBody.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(responseBody);
            }
        });
    }

    private List<RecordedRequest> requestsTo(String path) {
        return requests.stream().filter(request -> request.path().equals(path)).toList();
    }

    private RecordedRequest onlyRequestTo(String path) {
        List<RecordedRequest> matches = requestsTo(path);
        assertThat(matches).hasSize(1);
        return matches.get(0);
    }

    private record RecordedRequest(String method, String path, Map<String, List<String>> headers, String body) {

        String header(String name) {
            return headers.entrySet().stream()
                    .filter(header -> header.getKey().equalsIgnoreCase(name))
                    .flatMap(header -> header.getValue().stream())
                    .findFirst()
                    .orElse(null);
        }
    }
}
