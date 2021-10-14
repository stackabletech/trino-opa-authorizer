package tech.stackable.trino.opa;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemSecurityContext;

public class OpaAuthorizer implements SystemAccessControl {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    private final URI opaPolicyUri;

    public OpaAuthorizer(URI opaApiUri) {
        this.opaPolicyUri = opaApiUri;
    }

    @SuppressWarnings("unused")
    private static class OpaQuery {
        public OpaQueryInput input;
    }

    @SuppressWarnings("unused")
    private static class OpaQueryInput {
        public OpaQueryUser user;
        public OpaQueryRequest request;

        public OpaQueryInput() {
        }
    }

    @SuppressWarnings("unused")
    private static class OpaQueryRequest {
        public OpaTable table;
        public String column;
        public Set<String> columns;
        public String owner;

        public OpaQueryRequest() {
        }

        public OpaQueryRequest(OpaTable table) {
            this.table = table;
        }
    }

    @SuppressWarnings("unused")
    private static class OpaQueryUser {
        public final String name;

        public OpaQueryUser(String name) {
            this.name = name;
        }
    }

    @SuppressWarnings("unused")
    private static class OpaTable {
        public final String catalog;
        public final String schema;
        public final String table;

        public OpaTable(String catalogName) {
            this.catalog = catalogName;
            this.schema = null;
            this.table = null;
        }

        public OpaTable(CatalogSchemaName name) {
            this.catalog = name.getCatalogName();
            this.schema = name.getSchemaName();
            this.table = null;
        }

        public OpaTable(CatalogSchemaTableName name) {
            this.catalog = name.getCatalogName();
            this.schema = name.getSchemaTableName().getSchemaName();
            this.table = name.getSchemaTableName().getTableName();
        }
    }

    private static class OpaQueryResult {
        // boxed Boolean to detect not-present vs explicitly false
        public Boolean result;
    }

    private boolean queryOpa(String policyName, SystemSecurityContext context, OpaQueryRequest request) {
        String username = context.getIdentity().getUser();
        OpaQueryInput input = new OpaQueryInput();
        input.user = new OpaQueryUser(username);
        input.request = request;
        byte[] queryJson;
        try {
            OpaQuery query = new OpaQuery();
            query.input = input;
            queryJson = json.writeValueAsBytes(query);
        } catch (JsonProcessingException e) {
            throw new OpaQueryException.SerializeFailed(e);
        }
        HttpResponse<String> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(opaPolicyUri.resolve(policyName)).header("Content-Type", "application/json")
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

    private boolean canAccessCatalog(SystemSecurityContext context, String catalogName) {
        return queryOpa("can_access_catalog", context, new OpaQueryRequest(new OpaTable(catalogName)));
    }

    private boolean canAccessSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        return queryOpa("can_access_schema", context, new OpaQueryRequest(new OpaTable(schema)));
    }

    private boolean canAccessTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        return queryOpa("can_access_table", context, new OpaQueryRequest(new OpaTable(table)));
    }

    private boolean canAccessColumn(SystemSecurityContext context, CatalogSchemaTableName table, String column) {
        OpaQueryRequest request = new OpaQueryRequest(new OpaTable(table));
        request.column = column;
        return queryOpa("can_access_column", context, request);
    }

    private boolean canViewQueryOwnedBy(SystemSecurityContext context, String owner) {
        OpaQueryRequest request = new OpaQueryRequest();
        request.owner = owner;
        return queryOpa("can_view_query_owned_by", context, request);
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
        if (!canAccessCatalog(context, catalogName)) {
            AccessDeniedException.denyCatalogAccess(catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
        return catalogs.parallelStream().filter(catalog -> canAccessCatalog(context, catalog))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
        return schemaNames.parallelStream()
                .filter(schema -> canAccessSchema(context, new CatalogSchemaName(catalogName, schema)))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName,
            Set<SchemaTableName> tableNames) {
        return tableNames.parallelStream()
                .filter(table -> canAccessTable(context, new CatalogSchemaTableName(catalogName, table)))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        return columns.parallelStream().filter(column -> canAccessColumn(context, table, column))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> filterViewQueryOwnedBy(SystemSecurityContext context, Set<String> queryOwners) {
        return queryOwners.parallelStream().filter(owner -> canViewQueryOwnedBy(context, owner))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
        if (!queryOpa("can_show_schemas", context, new OpaQueryRequest(new OpaTable(catalogName)))) {
            AccessDeniedException.denyShowSchemas(" of catalog " + catalogName);
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
        if (!queryOpa("can_show_tables", context, new OpaQueryRequest(new OpaTable(schema)))) {
            AccessDeniedException.denyShowTables(schema.getSchemaName(), " in catalog " + schema.getCatalogName());
        }
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table,
            Set<String> columns) {
        OpaQueryRequest request = new OpaQueryRequest(new OpaTable(table));
        request.columns = columns;
        if (!queryOpa("can_select_from_columns", context, request)) {
            AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
        }
    }
}
