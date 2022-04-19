package tech.stackable.trino.opa;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.eventlistener.EventListener;
import io.trino.spi.security.*;
import io.trino.spi.type.Type;

public class OpaAuthorizer implements SystemAccessControl {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper json;
    private final URI opaPolicyUri;

    public OpaAuthorizer(URI opaPolicyUri) {
        this.opaPolicyUri = opaPolicyUri;
        this.json = new ObjectMapper();
        // do not include null values
        this.json.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        // deal with Optional<T> values
        this.json.registerModule(new Jdk8Module());
    }

    private static class OpaQuery {
        public OpaQueryInput input;
        public OpaQuery(OpaQueryInput input) {
            this.input = input;
        }
    }

    private static class OpaQueryResult {
        // boxed Boolean to detect not-present vs explicitly false
        public Boolean result;
    }

    private boolean queryOpa(OpaQueryInput input) {
        byte[] queryJson;

        OpaQuery query = new OpaQuery(input);

        try {
            queryJson = json.writeValueAsBytes(query);
        } catch (JsonProcessingException e) {
            throw new OpaQueryException.SerializeFailed(e);
        }
        HttpResponse<String> response;
        try {
            response = httpClient.send(
                    HttpRequest.newBuilder(opaPolicyUri).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(queryJson)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            throw new OpaQueryException.QueryFailed(e);
        }
        switch (response.statusCode()) {
            case 200:
                break;
            case 404:
                throw new OpaQueryException.PolicyNotFound(opaPolicyUri.toString());
            default:
                throw new OpaQueryException.OpaServerError(opaPolicyUri.toString(), response);
        }
        String responseBody = response.body();
        OpaQueryResult result;
        try {
            result = json.readValue(responseBody, OpaQueryResult.class);
        } catch (Exception e) {
            throw new OpaQueryException.DeserializeFailed(e);
        }
        if (result.result == null) {
            return false;
        }
        return result.result;
    }

    @Override
    public void checkCanImpersonateUser(SystemSecurityContext context, String userName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().user(new OpaQueryInputResource.User(userName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ImpersonateUser", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanImpersonateUser(context, userName);
        }
    }

    @Override
    // TODO: This method is still called even if deprecated. We just call the checkImpersonateUser method which it replaces.
    public void checkCanSetUser(Optional<Principal> principal, String userName) {
        SystemSecurityContext context = new SystemSecurityContext(new Identity.Builder(userName).withPrincipal(principal).build(), Optional.empty());
        checkCanImpersonateUser(context, userName);

//        SystemSecurityContext context = new SystemSecurityContext(new Identity.Builder(userName).withPrincipal(principal).build(), Optional.empty());
//        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().user(new OpaQueryInputResource.User(userName)).build();
//        OpaQueryInputAction action = new OpaQueryInputAction("SetUser", resource);
//        OpaQueryInput input = new OpaQueryInput(context, action);
//
//        if (!queryOpa(input)) {
//            AccessDeniedException.denySetUser(principal, userName);
//        }
    }

    @Override
    public void checkCanExecuteQuery(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ExecuteQuery");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanExecuteQuery(context);
        }
    }

    @Override
    public void checkCanViewQueryOwnedBy(SystemSecurityContext context, Identity queryOwner) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().query(new OpaQueryInputResource.Query(queryOwner)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ViewQueryOwnedBy", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanViewQueryOwnedBy(context, queryOwner);
        }
    }

    @Override
    public Collection<Identity> filterViewQueryOwnedBy(SystemSecurityContext context, Collection<Identity> queryOwners) {
        return queryOwners.parallelStream().filter(queryOwner -> queryOpa(
                new OpaQueryInput(context,
                        new OpaQueryInputAction("FilterViewQueryOwnedBy", new OpaQueryInputResource.Builder()
                                .query(new OpaQueryInputResource.Query(queryOwner)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanKillQueryOwnedBy(SystemSecurityContext context, Identity queryOwner) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().query(new OpaQueryInputResource.Query(queryOwner)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("KillQueryOwnedBy", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanKillQueryOwnedBy(context, queryOwner);
        }
    }

    @Override
    public void checkCanReadSystemInformation(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ReadSystemInformation");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanReadSystemInformation(context);
        }
    }

    @Override
    public void checkCanWriteSystemInformation(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("WriteSystemInformation");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanWriteSystemInformation(context);
        }
    }

    @Override
    public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().systemSessionProperty(new OpaQueryInputResource.SystemSessionProperty(propertyName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetSystemSessionProperty", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetSystemSessionProperty(context, propertyName);
        }
    }

    @Override
    public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().catalog(new OpaQueryInputResource.Catalog(catalogName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("AccessCatalog", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanAccessCatalog(context, catalogName);
        }
    }

    @Override
    public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
        return catalogs.parallelStream().filter(catalog -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction("FilterCatalogs", new OpaQueryInputResource.Builder()
                                        .catalog(new OpaQueryInputResource.Catalog(catalog)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schema)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateSchema", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateSchema(context, schema);
        }
    }

    @Override
    public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schema)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropSchema", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropSchema(context, schema);
        }
    }

    @Override
    public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schema, newSchemaName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RenameSchema", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameSchema(context, schema, newSchemaName);
        }
    }

    @Override
    public void checkCanSetSchemaAuthorization(SystemSecurityContext context, CatalogSchemaName schema, TrinoPrincipal principal) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schema, principal)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetSchemaAuthorization", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetSchemaAuthorization(context, schema, principal);
        }
    }

    @Override
    public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(catalogName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ShowSchemas", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowSchemas(context, catalogName);
        }
    }

    @Override
    public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
        return schemaNames.parallelStream().filter(schemaName -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction("FilterSchemas", new OpaQueryInputResource.Builder()
                                        .schema(new OpaQueryInputResource.CatalogSchema(new CatalogSchemaName(catalogName, schemaName))).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowCreateSchema(SystemSecurityContext context, CatalogSchemaName schemaName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schemaName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ShowCreateSchema", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowCreateSchema(context, schemaName);
        }
    }

    @Override
    public void checkCanShowCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ShowCreateTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowCreateTable(context, table);
        }
    }

    @Override
    public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Object> properties) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, properties)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateTable(context, table, properties);
        }
    }

    @Override
    public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropTable(context, table);
        }
    }

    @Override
    public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, newTable)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RenameTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameTable(context, table, newTable);
        }
    }

    @Override
    public void checkCanSetTableProperties(SystemSecurityContext context, CatalogSchemaTableName table, Map<String, Optional<Object>> properties) {
        HashMap transformed_properties = new HashMap<String, String>();
        for (Map.Entry<String, Optional<Object>> entry : properties.entrySet()) {
             transformed_properties.put(entry.getKey(), entry.getValue().orElse(""));
        }

        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, transformed_properties)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetTableProperties", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableProperties(context, table, properties);
        }
    }

    @Override
    public void checkCanSetTableComment(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetTableComment", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableComment(context, table);
        }
    }

    @Override
    public void checkCanSetColumnComment(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetColumnComment", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetColumnComment(context, table);
        }
    }

    @Override
    public void checkCanShowTables(SystemSecurityContext context, CatalogSchemaName schema) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().schema(new OpaQueryInputResource.CatalogSchema(schema)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ShowTables", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowTables(context, schema);
        }
    }

    @Override
    public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
        return tableNames.parallelStream().filter(tableName -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction("FilterTables", new OpaQueryInputResource.Builder()
                                        .table(new OpaQueryInputResource.Table(catalogName, tableName)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanShowColumns(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ShowColumns", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowColumns(context, table);
        }
    }

    @Override
    public Set<String> filterColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        return columns.parallelStream().filter(column -> queryOpa(
                        new OpaQueryInput(context,
                                new OpaQueryInputAction("FilterColumns", new OpaQueryInputResource.Builder()
                                        .table(new OpaQueryInputResource.Table(table, column)).build()))))
                .collect(Collectors.toSet());
    }

    @Override
    public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("AddColumn", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanAddColumn(context, table);
        }
    }

    @Override
    public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropColumn", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropColumn(context, table);
        }
    }

    @Override
    public void checkCanSetTableAuthorization(SystemSecurityContext context, CatalogSchemaTableName table, TrinoPrincipal principal) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, principal)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetTableAuthorization", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetTableAuthorization(context, table, principal);
        }
    }

    @Override
    public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RenameColumn", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameColumn(context, table);
        }
    }

    @Override
    public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, columns)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SelectFromColumns", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSelectFromColumns(context, table, columns);
        }
    }

    @Override
    public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("InsertIntoTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanInsertIntoTable(context, table);
        }
    }

    @Override
    public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DeleteFromTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDeleteFromTable(context, table);
        }
    }

    @Override
    public void checkCanTruncateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("TruncateTable", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanTruncateTable(context, table);
        }
    }

    @Override
    public void checkCanUpdateTableColumns(SystemSecurityContext securityContext, CatalogSchemaTableName table, Set<String> updatedColumnNames) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().table(new OpaQueryInputResource.Table(table, updatedColumnNames)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("UpdateTableColumns", resource);
        OpaQueryInput input = new OpaQueryInput(securityContext, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanUpdateTableColumns(securityContext, table, updatedColumnNames);
        }
    }

    @Override
    public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(view)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateView(context, view);
        }
    }

    @Override
    public void checkCanRenameView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(view, newView)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RenameView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameView(context, view, newView);
        }
    }

    @Override
    public void checkCanSetViewAuthorization(SystemSecurityContext context, CatalogSchemaTableName view, TrinoPrincipal principal) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(view, principal)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetViewAuthorization", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetViewAuthorization(context, view, principal);
        }
    }

    @Override
    public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(view)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropView(context, view);
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(table, columns)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateViewWithSelectFromColumns", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateViewWithSelectFromColumns(context, table, columns);
        }
    }

    @Override
    public void checkCanCreateMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Object> properties) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(materializedView, properties)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateMaterializedView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateMaterializedView(context, materializedView, properties);
        }
    }

    @Override
    public void checkCanRefreshMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(materializedView)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RefreshMaterializedView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRefreshMaterializedView(context, materializedView);
        }
    }

    @Override
    public void checkCanSetMaterializedViewProperties(SystemSecurityContext context, CatalogSchemaTableName materializedView, Map<String, Optional<Object>> properties) {
        HashMap transformed_properties = new HashMap<String, String>();
        for (Map.Entry<String, Optional<Object>> entry : properties.entrySet()) {
            transformed_properties.put(entry.getKey(), entry.getValue().orElse(""));
        }

        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(materializedView, transformed_properties)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetMaterializedViewProperties", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetMaterializedViewProperties(context, materializedView, properties);
        }
    }

    @Override
    public void checkCanDropMaterializedView(SystemSecurityContext context, CatalogSchemaTableName materializedView) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(materializedView)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropMaterializedView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropMaterializedView(context, materializedView);
        }
    }

    @Override
    public void checkCanRenameMaterializedView(SystemSecurityContext context, CatalogSchemaTableName view, CatalogSchemaTableName newView) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().view(new OpaQueryInputResource.View(view, newView)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RenameMaterializedView", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRenameMaterializedView(context, view, newView);
        }
    }

    @Override
    public void checkCanGrantExecuteFunctionPrivilege(SystemSecurityContext context, String functionName, TrinoPrincipal grantee, boolean grantOption) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(functionName, grantee, grantOption)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("GrantExecuteFunctionPrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanGrantExecuteFunctionPrivilege(context, functionName, grantee, grantOption);
        }
    }

    @Override
    public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().catalog(new OpaQueryInputResource.Catalog(catalogName, propertyName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("SetCatalogSessionProperty", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
        }
    }

    @Override
    public void checkCanGrantSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee, boolean grantOption) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, schema, grantee, grantOption)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("GrantSchemaPrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanGrantSchemaPrivilege(context, privilege, schema, grantee, grantOption);
        }
    }

    @Override
    public void checkCanDenySchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, schema, grantee)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DenySchemaPrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDenySchemaPrivilege(context, privilege, schema, grantee);
        }
    }

    @Override
    public void checkCanRevokeSchemaPrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaName schema, TrinoPrincipal revokee, boolean grantOption) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, schema, revokee, grantOption)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RevokeSchemaPrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRevokeSchemaPrivilege(context, privilege, schema, revokee, grantOption);
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean grantOption) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, table, grantee, grantOption)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("GrantTablePrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanGrantTablePrivilege(context, privilege, table, grantee, grantOption);
        }
    }

    @Override
    public void checkCanDenyTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, table, grantee)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DenyTablePrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDenyTablePrivilege(context, privilege, table, grantee);
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal revokee, boolean grantOption) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().authorization(new OpaQueryInputResource.Authorization(privilege, table, revokee, grantOption)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RevokeTablePrivilege", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRevokeTablePrivilege(context, privilege, table, revokee, grantOption);
        }
    }

    @Override
    public void checkCanShowRoles(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ShowRoles");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowRoles(context);
        }
    }

    @Override
    public void checkCanCreateRole(SystemSecurityContext context, String role, Optional<TrinoPrincipal> grantor) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().role(new OpaQueryInputResource.Role(role, grantor)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("CreateRole", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanCreateRole(context, role, grantor);
        }
    }

    @Override
    public void checkCanDropRole(SystemSecurityContext context, String role) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().role(new OpaQueryInputResource.Role(role)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("DropRole", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanDropRole(context, role);
        }
    }

    @Override
    public void checkCanGrantRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().role(new OpaQueryInputResource.Role(roles, grantees, adminOption, grantor)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("GrantRoles", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanGrantRoles(context, roles, grantees, adminOption, grantor);
        }
    }

    @Override
    public void checkCanRevokeRoles(SystemSecurityContext context, Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().role(new OpaQueryInputResource.Role(roles, grantees, adminOption, grantor)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("RevokeRoles", resource);
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanRevokeRoles(context, roles, grantees, adminOption, grantor);
        }
    }

    @Override
    public void checkCanShowRoleAuthorizationDescriptors(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ShowRoleAuthorizationDescriptors");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowRoleAuthorizationDescriptors(context);
        }
    }

    @Override
    public void checkCanShowCurrentRoles(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ShowCurrentRoles");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowCurrentRoles(context);
        }
    }

    @Override
    public void checkCanShowRoleGrants(SystemSecurityContext context) {
        OpaQueryInputAction action = new OpaQueryInputAction("ShowRoleGrants");
        OpaQueryInput input = new OpaQueryInput(context, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanShowRoleGrants(context);
        }
    }

    @Override
    public void checkCanExecuteProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaRoutineName procedure) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().execution(new OpaQueryInputResource.Execution(procedure)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ExecuteProcedure", resource);
        OpaQueryInput input = new OpaQueryInput(systemSecurityContext, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanExecuteProcedure(systemSecurityContext, procedure);
        }
    }

    @Override
    public void checkCanExecuteFunction(SystemSecurityContext systemSecurityContext, String functionName) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().execution(new OpaQueryInputResource.Execution(functionName)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ExecuteFunction", resource);
        OpaQueryInput input = new OpaQueryInput(systemSecurityContext, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanExecuteFunction(systemSecurityContext, functionName);
        }
    }

    @Override
    public void checkCanExecuteTableProcedure(SystemSecurityContext systemSecurityContext, CatalogSchemaTableName table, String procedure) {
        OpaQueryInputResource resource = new OpaQueryInputResource.Builder().execution(new OpaQueryInputResource.Execution(table, procedure)).build();
        OpaQueryInputAction action = new OpaQueryInputAction("ExecuteTableProcedure", resource);
        OpaQueryInput input = new OpaQueryInput(systemSecurityContext, action);

        if (!queryOpa(input)) {
            SystemAccessControl.super.checkCanExecuteTableProcedure(systemSecurityContext, table, procedure);
        }
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
