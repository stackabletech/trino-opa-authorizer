package tech.stackable.trino.opa;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.eventlistener.EventListener;
import io.trino.spi.security.*;
import io.trino.spi.type.Type;

import javax.management.Query;

public class OpaAuthorizer implements SystemAccessControl {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();
    private final URI opaPolicyUri;

    public OpaAuthorizer(URI opaPolicyUri) {
        this.opaPolicyUri = opaPolicyUri;
    }

    @SuppressWarnings("unused")
    private static class OpaQuery {
        public OpaQueryInput input;
    }

    private static class OpaQueryResult {
        // boxed Boolean to detect not-present vs explicitly false
        public Boolean result;
    }

    private String getCurrentMethodName() {
        StackWalker walker = StackWalker.getInstance();
        Optional<String> methodName = walker.walk(frames -> frames
                .findFirst()
                .map(StackWalker.StackFrame::getMethodName));

        return methodName.get();
    }

    private boolean queryOpa(OpaQueryInput input) {
        String policyName = "allow";
        byte[] queryJson;
        try {
            queryJson = json.writeValueAsBytes(input);
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

    @Override
    public void checkCanImpersonateUser(SystemSecurityContext context, String userName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().user(new OpaQueryInputResource.User(userName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanImpersonateUser(context, userName);
        }
    }

    @Override
    public void checkCanExecuteQuery(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName());
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanExecuteQuery(context);
        }
    }

    @Override
    public void checkCanViewQueryOwnedBy(SystemSecurityContext context, Identity queryOwner) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().query(new OpaQueryInputResource.Query(queryOwner)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanViewQueryOwnedBy(context, queryOwner);
        }
    }

    @Override
    public Collection<Identity> filterViewQueryOwnedBy(SystemSecurityContext context, Collection<Identity> queryOwners) {
        return queryOwners.parallelStream().filter(queryOwner -> queryOpa(
                new OpaQueryInput(context,
                        new OpaQueryInputAction(getCurrentMethodName(), new OpaQueryInputResource.Builder()
                                .query(new OpaQueryInputResource.Query(queryOwner)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanKillQueryOwnedBy(SystemSecurityContext context, Identity queryOwner) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().query(new OpaQueryInputResource.Query(queryOwner)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanKillQueryOwnedBy(context, queryOwner);
        }
    }

    @Override
    public void checkCanReadSystemInformation(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName());
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanReadSystemInformation(context);
        }
    }

    @Override
    public void checkCanWriteSystemInformation(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName());
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanWriteSystemInformation(context);
        }
    }

    @Override
    public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().systemSessionProperty(new OpaQueryInputResource.SystemSessionProperty(propertyName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetSystemSessionProperty(context, propertyName);
        }
    }

    @Override
    public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().catalog(new OpaQueryInputResource.Catalog(catalogName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanAccessCatalog(context, catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
        return catalogs.parallelStream().filter(catalog -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction(getCurrentMethodName(), new OpaQueryInputResource.Builder()
                                        .catalog(new OpaQueryInputResource.Catalog(catalog)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(schema)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateSchema(context, schema);
        }
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(schema)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropSchema(context, schema);
        }
    }

    @Override
    public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(schema, newSchemaName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameSchema(context, schema, newSchemaName);
        }
    }

    @Override
    public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, TrinoPrincipal principal) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(schema, principal)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetSchemaAuthorization(context, schema, principal);
        }
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(catalogName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowSchemas(context, catalogName);
        }
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
        return schemaNames.parallelStream().filter(schemaName -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction(getCurrentMethodName(), new OpaQueryInputResource.Builder()
                                        .schema(new OpaQueryInputResource.Schema(new CatalogSchemaName(catalogName, schemaName))).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schemaName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.Schema(schemaName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction(getCurrentMethodName(), resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowCreateSchema(context, schemaName);
        }
    }

    @Override
    public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanShowCreateTable")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowCreateTable(context, table);
        }
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Object> properties) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanCreateTable")
                        .catalogSchemaTableName(table)
                        .properties(properties)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateTable(context, table, properties);
        }
    }

    @Override
    public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanDropTable")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropTable(context, table);
        }
    }

    @Override
    public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanRenameTable")
                        .catalogSchemaTableName(table)
                        .newCatalogSchemaTableName(newTable)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameTable(context, table, newTable);
        }
    }

    @Override
    public void checkCanSetTableProperties(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Optional<Object>> properties) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanSetTableProperties")
                        .catalogSchemaTableName(table)
                        .properties_opt(properties)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableProperties(context, table, properties);
        }
    }

    @Override
    public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanSetTableComment")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableComment(context, table);
        }
    }

    @Override
    public void checkCanSetColumnComment(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanSetColumnComment")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetColumnComment(context, table);
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanShowTables")
                        .catalogSchemaName(schema)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowTables(context, schema);
        }
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
        return tableNames.parallelStream().filter(tableName -> queryOpa(new OpaQueryInput.Builder(context)
                        .action(new OpaQueryInputAction.Builder("filterTables")
                                .schemaTableName(tableName)
                                .build())
                        .build()))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanShowColumns")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowColumns(context, table);
        }
    }

    @Override
    public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        return columns.parallelStream().filter(column -> queryOpa(new OpaQueryInput.Builder(context)
                        .action(new OpaQueryInputAction.Builder("filterColumns")
                                .column(column)
                                .build())
                        .build()))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanAddColumn")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanAddColumn(context, table);
        }
    }

    @Override
    public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanDropColumn")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropColumn(context, table);
        }
    }

    @Override
    public void checkCanSetTableAuthorization(SystemSecurityContext context, CatalogSchemaTableName table, TrinoPrincipal principal) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanSetTableAuthorization")
                        .catalogSchemaTableName(table)
                        .principal(principal)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableAuthorization(context, table, principal);
        }
    }

    @Override
    public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanRenameColumn")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameColumn(context, table);
        }
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanSelectFromColumns")
                        .catalogSchemaTableName(table)
                        .columns(columns)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSelectFromColumns(context, table, columns);
        }
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanInsertIntoTable")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanInsertIntoTable(context, table);
        }
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanDeleteFromTable")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDeleteFromTable(context, table);
        }
    }

    @Override
    public void checkCanTruncateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInput input = new OpaQueryInput.Builder(context)
                .action(new OpaQueryInputAction.Builder("checkCanTruncateTable")
                        .catalogSchemaTableName(table)
                        .build())
                .build();

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanTruncateTable(context, table);
        }
    }

    @Override
    public void checkCanUpdateTableColumns(SystemSecurityContext securityContext, CatalogSchemaTableName table, Set<String> updatedColumnNames) {
        SystemAccessControl.super.checkCanUpdateTableColumns(securityContext, table, updatedColumnNames);
    }

    @Override
    public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
        SystemAccessControl.super.checkCanCreateView(context, view);
    }

    @Override
    public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
        SystemAccessControl.super.checkCanRenameView(context, view, newView);
    }

    @Override
    public void checkCanSetViewAuthorization(SystemSecurityContext context, CatalogSchemaTableName view, TrinoPrincipal principal) {
        SystemAccessControl.super.checkCanSetViewAuthorization(context, view, principal);
    }

    @Override
    public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
        SystemAccessControl.super.checkCanDropView(context, view);
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        SystemAccessControl.super.checkCanCreateViewWithSelectFromColumns(context, table, columns);
    }

    @Override
    public void checkCanCreateMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Object> properties) {
        SystemAccessControl.super.checkCanCreateMaterializedView(context, materializedView, properties);
    }

    @Override
    public void checkCanRefreshMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView) {
        SystemAccessControl.super.checkCanRefreshMaterializedView(context, materializedView);
    }

    @Override
    public void checkCanSetMaterializedViewProperties(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Optional<Object>> properties) {
        SystemAccessControl.super.checkCanSetMaterializedViewProperties(context, materializedView, properties);
    }

    @Override
    public void checkCanDropMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView) {
        SystemAccessControl.super.checkCanDropMaterializedView(context, materializedView);
    }

    @Override
    public void checkCanRenameMaterializedView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
        SystemAccessControl.super.checkCanRenameMaterializedView(context, view, newView);
    }

    @Override
    public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, String functionName, TrinoPrincipal grantee, boolean grantOption) {
        SystemAccessControl.super.checkCanGrantExecuteFunctionPrivilege(context, functionName, grantee, grantOption);
    }

    @Override
    public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
        SystemAccessControl.super.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
    }

    @Override
    public void checkCanGrantSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee, boolean grantOption) {
        SystemAccessControl.super.checkCanGrantSchemaPrivilege(context, privilege, schema, grantee, grantOption);
    }

    @Override
    public void checkCanDenySchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee) {
        SystemAccessControl.super.checkCanDenySchemaPrivilege(context, privilege, schema, grantee);
    }

    @Override
    public void checkCanRevokeSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal revokee, boolean grantOption) {
        SystemAccessControl.super.checkCanRevokeSchemaPrivilege(context, privilege, schema, revokee, grantOption);
    }

    @Override
    public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean grantOption) {
        SystemAccessControl.super.checkCanGrantTablePrivilege(context, privilege, table, grantee, grantOption);
    }

    @Override
    public void checkCanDenyTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee) {
        SystemAccessControl.super.checkCanDenyTablePrivilege(context, privilege, table, grantee);
    }

    @Override
    public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOption) {
        SystemAccessControl.super.checkCanRevokeTablePrivilege(context, privilege, table, revokee, grantOption);
    }

    @Override
    public void checkCanShowRoles(SystemSecurityContext context) {
        SystemAccessControl.super.checkCanShowRoles(context);
    }

    @Override
    public void checkCanCreateRole(SystemSecurityContext context, String role, Optional<TrinoPrincipal> grantor) {
        SystemAccessControl.super.checkCanCreateRole(context, role, grantor);
    }

    @Override
    public void checkCanDropRole(SystemSecurityContext context, String role) {
        SystemAccessControl.super.checkCanDropRole(context, role);
    }

    @Override
    public void checkCanGrantRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
        SystemAccessControl.super.checkCanGrantRoles(context, roles, grantees, adminOption, grantor);
    }

    @Override
    public void checkCanRevokeRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
        SystemAccessControl.super.checkCanRevokeRoles(context, roles, grantees, adminOption, grantor);
    }

    @Override
    public void checkCanShowRoleAuthorizationDescriptors(SystemSecurityContext context) {
        SystemAccessControl.super.checkCanShowRoleAuthorizationDescriptors(context);
    }

    @Override
    public void checkCanShowCurrentRoles(SystemSecurityContext context) {
        SystemAccessControl.super.checkCanShowCurrentRoles(context);
    }

    @Override
    public void checkCanShowRoleGrants(SystemSecurityContext context) {
        SystemAccessControl.super.checkCanShowRoleGrants(context);
    }

    @Override
    public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure) {
        SystemAccessControl.super.checkCanExecuteProcedure(systemSecurityContext, procedure);
    }

    @Override
    public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, String functionName) {
        SystemAccessControl.super.checkCanExecuteFunction(systemSecurityContext, functionName);
    }

    @Override
    public void checkCanExecuteTableProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaTableName table, String procedure) {
        SystemAccessControl.super.checkCanExecuteTableProcedure(systemSecurityContext, table, procedure);
    }

    @Override
    public List<ViewExpression> getRowFilters(SystemSecurityContext context, CatalogSchemaTableName tableName) {
        return SystemAccessControl.super.getRowFilters(context, tableName);
    }

    @Override
    public List<ViewExpression> getColumnMasks(SystemSecurityContext context, CatalogSchemaTableName tableName, String columnName, Type type) {
        return SystemAccessControl.super.getColumnMasks(context, tableName, columnName, type);
    }

    @Override
    public Iterable<EventListener> getEventListeners() {
        return SystemAccessControl.super.getEventListeners();
    }
}
