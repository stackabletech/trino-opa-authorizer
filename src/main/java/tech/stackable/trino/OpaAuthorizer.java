package tech.stackable.trino;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;

public class OpaAuthorizer implements SystemAccessControl {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    private static class OpaQuery<Ctx> {
        public final OpaQueryInput<Ctx> input;

        public OpaQuery(OpaQueryInput<Ctx> input) {
            this.input = input;
        }
    }

    private static class OpaQueryInput<Ctx> {
        public final OpaQueryUser user;
        public final Ctx context;

        public OpaQueryInput(OpaQueryUser user, Ctx context) {
            this.user = user;
            this.context = context;
        }
    }

    private static class OpaQueryUser {
        public final String name;

        public OpaQueryUser(String name) {
            this.name = name;
        }
    }

    private static class OpaTableCtx {
        public final String catalog;
        public final String schema;
        public final String table;

        public OpaTableCtx(String catalogName) {
            this.catalog = catalogName;
            this.schema = null;
            this.table = null;
        }

        public OpaTableCtx(CatalogSchemaTableName name) {
            this.catalog = name.getCatalogName();
            this.schema = name.getSchemaTableName().getSchemaName();
            this.table = name.getSchemaTableName().getTableName();
        }
    }

    private static class OpaQueryResult {
        // boxed Boolean to detect not-present vs explicitly false
        public Boolean result;
    }

    private <Ctx> boolean queryOpa(String policyName, SystemSecurityContext securityContext, Ctx queryContext) {
        String username = securityContext.getIdentity().getUser();
        OpaQueryInput<Ctx> query = new OpaQueryInput<>(new OpaQueryUser(username), queryContext);
        byte[] queryJson;
        try {
            queryJson = json.writeValueAsBytes(query);
        } catch (JsonProcessingException e) {
            throw new OpaQueryException.SerializeFailed(e);
        }
        HttpResponse<String> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(URI.create("http://localhost:8181/v1/data/trino/" + policyName))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(queryJson)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new OpaQueryException.QueryFailed(e);
        }
        switch (response.statusCode()) {
            case 200:
                break;
            case 404:
                throw new OpaQueryException.PolicyNotFound(policyName);
            default:
                throw new OpaQueryException.OpaServerError(policyName, response);
        }
        String responseBody = response.body();
        OpaQueryResult result;
        try {
            result = json.readValue(responseBody, OpaQueryResult.class);
        } catch (Exception e) {
            throw new OpaQueryException.DeserializeFailed(e);
        }
        if (result.result == null) {
            throw new OpaQueryException.PolicyNotFound(policyName);
        }
        return result.result;
    }

    @Override
    public void checkCanSetUser(Optional<Principal> principal, String userName) {
        if (!principal.map(p -> p.getName()).equals(Optional.of(userName))) {
            AccessDeniedException.denySetUser(principal, userName);
        }
    }

    @Override
    public void checkCanExecuteQuery(SystemSecurityContext context) {
        if (!queryOpa("can_execute_query", context, null)) {
            AccessDeniedException.denyExecuteQuery();
        }
    }

    @Override
    public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
        if (!queryOpa("can_access_catalog", context, new OpaTableCtx(catalogName))) {
            AccessDeniedException.denyExecuteQuery();
        }
    }
}
