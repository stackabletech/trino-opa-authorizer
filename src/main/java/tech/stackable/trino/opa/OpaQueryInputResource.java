package tech.stackable.trino.opa;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.function.FunctionKind;
import io.trino.spi.security.Identity;
import io.trino.spi.security.TrinoPrincipal;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class OpaQueryInputResource {
    public User user;
    public Query query;
    public SystemSessionProperty systemSessionProperty;
    public Catalog catalog;
    public CatalogSchema schema;
    public Table table;
    public View view;
    public Authorization authorization;
    public Role role;
    public Execution execution;

    public static class User {
        public String name;
        public User(String name) { this.name = name; }
    }

    public static class Query {
        public Identity owner;
        public Query(Identity owner) { this.owner = owner; }
    }

    public static class SystemSessionProperty {
        public String property;
        public SystemSessionProperty(String property) { this.property = property; }
    }

    public static class Catalog {
        public String name;
        public String propertyName;
        public Catalog(String name) { this.name = name; }

        public Catalog(String name, String propertyName) {
            this.name = name;
            this.propertyName = propertyName;
        }
    }

    public static class CatalogSchema {
        public CatalogSchemaName catalogSchemaName;
        public String newCatalogSchemaName;
        public TrinoPrincipal principal;
        public String catalogName;
        public Map<String, Object> properties;

        public CatalogSchema(CatalogSchemaName schema) { this.catalogSchemaName = schema; }

        public CatalogSchema(String catalogName) { this.catalogName = catalogName; }

        public CatalogSchema(CatalogSchemaName catalogSchemaName, String newCatalogSchemaName) {
            this.catalogSchemaName = catalogSchemaName;
            this.newCatalogSchemaName = newCatalogSchemaName;
        }

        public CatalogSchema(CatalogSchemaName catalogSchemaName, TrinoPrincipal principal) {
            this.catalogSchemaName = catalogSchemaName;
            this.principal = principal;
        }

        public CatalogSchema(CatalogSchemaName catalogSchemaName, Map<String, Object> properties) {
            this.catalogSchemaName = catalogSchemaName;
            this.properties = properties;
        }
    }

    public static class Table {
        public String catalogName;
        public CatalogSchemaTableName catalogSchemaTableName;
        public Map<String, Object> properties;
        public CatalogSchemaTableName newCatalogSchemaTableName;
        public SchemaTableName schemaTableName;
        public String column;
        public TrinoPrincipal principal;
        public Set<String> columns;

        public Table(CatalogSchemaTableName catalogSchemaTableName) {
            this.catalogSchemaTableName = catalogSchemaTableName;
        }

        public Table(CatalogSchemaTableName catalogSchemaTableName, Map<String, Object> properties) {
            this.catalogSchemaTableName = catalogSchemaTableName;
            this.properties = properties;
        }

        public Table(CatalogSchemaTableName catalogSchemaTableName, CatalogSchemaTableName newCatalogSchemaTableName) {
            this.catalogSchemaTableName = catalogSchemaTableName;
            this.newCatalogSchemaTableName = newCatalogSchemaTableName;
        }

        public Table(String catalogName, SchemaTableName schemaTableName) {
            this.schemaTableName = schemaTableName;
        }

        public Table(CatalogSchemaTableName catalogSchemaTableName, String column) {
            this.catalogSchemaTableName = catalogSchemaTableName;
            this.column = column;
        }

        public Table(CatalogSchemaTableName catalogSchemaTableName, Set<String> columns) {
            this.catalogSchemaTableName = catalogSchemaTableName;
            this.columns = columns;
        }

        public Table(CatalogSchemaTableName catalogSchemaTableName, TrinoPrincipal principal) {
            this.catalogSchemaTableName = catalogSchemaTableName;
            this.principal = principal;
        }
    }

    public static class View {
        public CatalogSchemaTableName view;
        public CatalogSchemaTableName newView;
        public TrinoPrincipal principal;
        public Set<String> columns;
        public Map<String, Object> properties;

        public View(CatalogSchemaTableName view) {
            this.view = view;
        }

        public View(CatalogSchemaTableName view, CatalogSchemaTableName newView) {
            this.view = view;
            this.newView = newView;
        }

        public View(CatalogSchemaTableName view, TrinoPrincipal principal) {
            this.view = view;
            this.principal = principal;
        }

        public View(CatalogSchemaTableName view, Set<String> columns) {
            this.view = view;
            this.columns = columns;
        }

        public View(CatalogSchemaTableName view, Map<String, Object> properties) {
            this.view = view;
            this.properties = properties;
        }
    }

    public static class Authorization {
        public String functionName;
        public TrinoPrincipal grantee;
        public boolean grantOption;
        public CatalogSchemaName schema;
        public io.trino.spi.security.Privilege privilege;
        public CatalogSchemaTableName table;
        public FunctionKind functionKind;

        public Authorization(String functionName, TrinoPrincipal grantee, boolean grantOption) {
            this.functionName = functionName;
            this.grantee = grantee;
            this.grantOption = grantOption;
        }

        public Authorization(io.trino.spi.security.Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee, boolean grantOption) {
            this.privilege = privilege;
            this.schema = schema;
            this.grantee = grantee;
            this.grantOption = grantOption;
        }

        public Authorization(io.trino.spi.security.Privilege privilege, CatalogSchemaName schema, TrinoPrincipal grantee) {
            this.privilege = privilege;
            this.schema = schema;
            this.grantee = grantee;
        }

        public Authorization(io.trino.spi.security.Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee, boolean grantOption) {
            this.privilege = privilege;
            this.table = table;
            this.grantee = grantee;
            this.grantOption = grantOption;
        }

        public Authorization(io.trino.spi.security.Privilege privilege, CatalogSchemaTableName table, TrinoPrincipal grantee) {
            this.privilege = privilege;
            this.table = table;
            this.grantee = grantee;
        }

        public Authorization(FunctionKind functionKind, String functionName, TrinoPrincipal grantee, boolean grantOption) {
            this.functionKind = functionKind;
            this.functionName = functionName;
            this.grantee = grantee;
            this.grantOption = grantOption;
        }
    }

    public static class Role {
        public String name;
        public TrinoPrincipal grantor;
        public Set<String> names;
        public Set<TrinoPrincipal> grantees;
        public boolean adminOption;

        public Role(String name) {
            this.name = name;
        }

        public Role(String name, Optional<TrinoPrincipal> grantor) {
            this.name = name;
            this.grantor = grantor.orElse(null);
        }

        public Role(Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
            this.names = roles;
            this.grantees = grantees;
            this.adminOption = adminOption;
            this.grantor = grantor.orElse(null);
        }
    }

    public static class Execution {
        public CatalogSchemaRoutineName routine;
        public String functionName;
        public String procedure;
        public CatalogSchemaTableName table;
        public FunctionKind functionKind;
        public Execution(CatalogSchemaRoutineName routine) {
            this.routine = routine;
        }

        public Execution(String functionName) {
            this.functionName = functionName;
        }

        public Execution(CatalogSchemaTableName table, String procedure) {
            this.table = table;
            this.procedure = procedure;
        }

        public Execution(FunctionKind functionKind, CatalogSchemaRoutineName routine) {
            this.routine = routine;
            this.functionKind = functionKind;
        }
    }

    public OpaQueryInputResource(OpaQueryInputResource.Builder builder) {
        this.user = builder.user;
        this.query = builder.query;
        this.systemSessionProperty = builder.systemSessionProperty;
        this.catalog = builder.catalog;
        this.schema = builder.schema;
        this.table = builder.table;
        this.view = builder.view;
        this.authorization = builder.authorization;
        this.role = builder.role;
        this.execution = builder.execution;
    }

    public static class Builder {
        private User user;
        private Query query;
        private SystemSessionProperty systemSessionProperty;
        private Catalog catalog;
        private CatalogSchema schema;
        private Table table;
        private View view;
        private Authorization authorization;
        private Role role;
        private Execution execution;

        public Builder user(User user) {
            this.user = user;
            return this;
        }

        public Builder query(Query query) {
            this.query = query;
            return this;
        }

        public Builder systemSessionProperty(SystemSessionProperty systemSessionProperty) {
            this.systemSessionProperty = systemSessionProperty;
            return this;
        }

        public Builder catalog(Catalog catalog) {
            this.catalog = catalog;
            return this;
        }

        public Builder schema(CatalogSchema schema) {
            this.schema = schema;
            return this;
        }

        public Builder table(Table table) {
            this.table = table;
            return this;
        }

        public Builder view(View view) {
            this.view = view;
            return this;
        }

        public Builder authorization(Authorization authorization) {
            this.authorization = authorization;
            return this;
        }

        public Builder role(Role role) {
            this.role = role;
            return this;
        }

        public Builder execution(Execution execution) {
            this.execution = execution;
            return this;
        }

        public OpaQueryInputResource build() {
            OpaQueryInputResource input = new OpaQueryInputResource(this);
            return input;
        }
    }
}
