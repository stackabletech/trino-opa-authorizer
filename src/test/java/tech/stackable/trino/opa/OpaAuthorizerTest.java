package tech.stackable.trino.opa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import io.trino.Session;
import io.trino.execution.QueryIdGenerator;
import io.trino.metadata.SessionPropertyManager;
import io.trino.server.testing.TestingTrinoServer;
import io.trino.spi.security.Identity;
import io.trino.testing.MaterializedResult;
import io.trino.testing.MaterializedRow;
import io.trino.testing.TestingTrinoClient;

public class OpaAuthorizerTest {
    private static URI opaServerUri;
    private static Process opaServer;
    private static TestingTrinoServer trinoServer;
    private static TestingTrinoClient trinoClient;

    /**
     * Get an unused TCP port on a local interface from the system
     *
     * There is a minor race condition here, in that the port is deallocated before it is used
     * again, but this is more or less unavoidable when allocating a port for a subprocess without
     * FD-passing.
     */
    private static InetSocketAddress findAvailableTcpPort() throws IOException {
        Socket sock = new Socket();
        try {
            sock.bind(new InetSocketAddress("127.0.0.1", 0));
            return new InetSocketAddress(sock.getLocalAddress(), sock.getLocalPort());
        } finally {
            sock.close();
        }
    }

    private static void awaitSocketOpen(InetSocketAddress addr, int attempts, int timeoutMs)
            throws IOException, InterruptedException {
        for (int i = 0; i < attempts; ++i) {
            Socket socket = new Socket();
            try {
                socket.connect(addr, timeoutMs);
                return;
            } catch (SocketTimeoutException e) {
                // e.printStackTrace();
            } catch (IOException e) {
                // e.printStackTrace();
                Thread.sleep(timeoutMs);
            } finally {
                socket.close();
            }
        }
        throw new SocketTimeoutException("Timed out waiting for addr " + addr + " to be available ("
                + attempts + " attempts made at " + timeoutMs + "ms each)");
    }

    @BeforeAll
    public static void setupTrino() throws IOException, InterruptedException {
        InetSocketAddress opaSocket = findAvailableTcpPort();
        opaServer = new ProcessBuilder("opa", "run", "--server", "--addr",
                opaSocket.getHostString() + ":" + opaSocket.getPort()).inheritIO().start();
        awaitSocketOpen(opaSocket, 100, 200);
        opaServerUri =
                URI.create("http://" + opaSocket.getHostString() + ":" + opaSocket.getPort() + "/");

        QueryIdGenerator idGen = new QueryIdGenerator();
        Identity identity = Identity.forUser("bob").build();
        SessionPropertyManager sessionPropertyManager = new SessionPropertyManager();
        Session session = Session.builder(sessionPropertyManager)
                .setQueryId(idGen.createNextQueryId()).setIdentity(identity).build();
        trinoServer = TestingTrinoServer.builder()
                .setSystemAccessControls(Collections.singletonList(new OpaAuthorizer(opaServerUri.resolve("v1/data/trino/allow"))))
                .build();
        trinoClient = new TestingTrinoClient(trinoServer, session);
    }

    @AfterAll
    public static void teardownTrino() throws IOException {
        try {
            if (opaServer != null) {
                opaServer.destroy();
            }
        } finally {
            try {
                if (trinoClient != null) {
                    trinoClient.close();
                }
            } finally {
                if (trinoServer != null) {
                    trinoServer.close();
                }
            }
        }
    }

    private String stringOfLines(String... lines) {
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            out.append(line);
            out.append("\r\n");
        }
        return out.toString();
    }

    private void submitPolicy(String... policyLines) throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> policyRes =
                httpClient.send(
                        HttpRequest.newBuilder(opaServerUri.resolve("v1/policies/trino"))
                                .PUT(HttpRequest.BodyPublishers
                                        .ofString(stringOfLines(policyLines)))
                                .header("Content-Type", "text/plain").build(),
                        HttpResponse.BodyHandlers.ofString());
        assertEquals(policyRes.statusCode(), 200, "Failed to submit policy: " + policyRes.body());
    }

    @Test
    public void testShouldAllowQueryIfDirected() throws IOException, InterruptedException {
        submitPolicy(
            "package trino",
            "import future.keywords.in",
            "default allow = false",
            "allow {",
            "  is_bob",
            "  can_be_accessed_by_bob",
            "}",
            "is_bob() {",
            "  input.context.identity.user == \"bob\"",
            "}",
            "can_be_accessed_by_bob() { ",
            "  input.action.operation in [\"ImpersonateUser\", \"FilterCatalogs\", \"AccessCatalog\", \"ExecuteQuery\"]",
            "}"
        );
        List<String> catalogs = new ArrayList<>();
        MaterializedResult result =
                trinoClient.execute("SHOW CATALOGS").getResult();
        for (MaterializedRow row : result) {
            catalogs.add(row.getField(0).toString());
        }
        assertEquals(catalogs, Collections.singletonList("system"));
    }

    @Test
    public void testShouldDenyQueryIfDirected() throws IOException, InterruptedException {
        submitPolicy(
            "package trino",
            "import future.keywords.in",
            "default allow = false",
            "allow {",
            "  is_bob",
            "  can_be_accessed_by_bob",
            "}",
            "is_bob() {",
            "  input.context.identity.user == \"bob\"",
            "}",
            "can_be_accessed_by_bob() { ",
            "  input.action.operation in [\"ImpersonateUser\", \"FilterCatalogs\", \"AccessCatalog\", \"ExecuteQuery\"]",
            "}"
        );
        RuntimeException error = assertThrows(RuntimeException.class, () -> {
            trinoClient.execute("SHOW SCHEMAS IN system");
        });
        assertTrue(error.getMessage().contains("Access Denied"),
                "Error must mention 'Access Denied': " + error.getMessage());
    }
}
