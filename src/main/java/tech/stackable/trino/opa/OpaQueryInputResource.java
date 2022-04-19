package tech.stackable.trino.opa;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaRoutineName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.security.Identity;
import io.trino.spi.security.TrinoPrincipal;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class OpaQueryInputResource {
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

    public static class User {
        private String name;
        public User(String name) { this.name = name; }
    }

    public static class Query {
        private Identity owner;
        public Query(Identity owner) { this.owner = owner; }
    }

    public static class SystemSessionProperty {
        private String property;
        public SystemSessionProperty(String property) { this.property = property; }
    }

    public static class Catalog {
        private String name;
        private String propertyName;
        public Catalog(String name) { this.name = name; }

        public Catalog(String name, String propertyName) {
            this.name = name;
            this.propertyName = propertyName;
        }
    }

    public static class CatalogSchema {
        private CatalogSchemaName catalogSchemaName;
        private String newCatalogSchemaName;
        private TrinoPrincipal principal;
        private String catalogName;

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
    }

    public static class Table {
        private String catalogName;
        private CatalogSchemaTableName catalogSchemaTableName;
        private Map<String, Object> properties;
        private CatalogSchemaTableName newCatalogSchemaTableName;
        private SchemaTableName schemaTableName;
        private String column;
        private TrinoPrincipal principal;
        private Set<String> columns;

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
        private CatalogSchemaTableName view;
        private CatalogSchemaTableName newView;
        private TrinoPrincipal principal;
        private Set<String> columns;
        private Map<String, Object> properties;

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
        private String functionName;
        private TrinoPrincipal grantee;
        private boolean grantOption;
        private CatalogSchemaName schema;
        private io.trino.spi.security.Privilege privilege;
        private CatalogSchemaTableName table;

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
    }

    public static class Role {
        private String name;
        private TrinoPrincipal grantor;
        private Set<String> names;
        private Set<TrinoPrincipal> grantees;
        private boolean adminOption;

        public Role(String name) {
            this.name = name;
        }

        public Role(String name, Optional<TrinoPrincipal> grantor) {
            this.name = name;
            if (grantor.isPresent()) {
                this.grantor = grantor.get();
            }
        }

        public Role(Set<String> roles, Set<TrinoPrincipal> grantees, boolean adminOption, Optional<TrinoPrincipal> grantor) {
            this.names = roles;
            this.grantees = grantees;
            this.adminOption = adminOption;
            if (grantor.isPresent()) {
                this.grantor = grantor.get();
            }
        }
    }

    public static class Execution {
        private CatalogSchemaRoutineName routine;
        private String functionName;
        private String procedure;
        private CatalogSchemaTableName table;
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
    }

    private OpaQueryInputResource(OpaQueryInputResource.Builder builder) {
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
