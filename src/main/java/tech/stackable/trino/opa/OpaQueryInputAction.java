package tech.stackable.trino.opa;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.connector.CatalogSchemaTableName;
import io.trino.spi.connector.SchemaTableName;
import io.trino.spi.security.Identity;
import io.trino.spi.security.TrinoPrincipal;

import java.util.Map;
import java.util.Set;

public class OpaQueryInputAction {
    public enum Operation {
        CREATE,
        ACCESS,
        READ,
        WRITE,
        DROP,
        GRANT,
        REVOKE,
        KILL,
        IMPERSONATE,
        RENAME,
        EXECUTE,
        VIEW,
        FILTER,
        SET
    }

    private Operation operation;
    private OpaQueryInputResource resource;


//    private String userName;
//    private Identity queryOwner;
//    private String propertyName;
//    private String catalogName;
//    private CatalogSchemaName catalogSchemaName;
//    private String newSchemaName;
//    private TrinoPrincipal principal;
//    private CatalogSchemaTableName catalogSchemaTableName;
//    private Map<String, Object> properties;
//    private CatalogSchemaTableName newCatalogSchemaTableName;
//    private SchemaTableName schemaTableName;
//    private String column;
//    private Set<String> columns;

    private OpaQueryInputAction(OpaQueryInputAction.Builder builder) {
//        this.userName = builder.userName;
        this.operation = builder.operation;
        this.resource = builder.resource;
//        this.queryOwner = builder.queryOwner;
//        this.propertyName = builder.propertyName;
//        this.catalogName = builder.catalogName;
//        this.catalogSchemaName = builder.catalogSchemaName;
//        this.newSchemaName = builder.newSchemaName;
//        this.principal = builder.principal;
//        this.catalogSchemaTableName = builder.catalogSchemaTableName;
//        this.properties = builder.properties;
//        this.newCatalogSchemaTableName = builder.newCatalogSchemaTableName;
//        this.schemaTableName = builder.schemaTableName;
//        this.column = builder.column;
//        this.columns = builder.columns;
    }

    public static class Builder {
        private Operation operation;
        private OpaQueryInputResource resource;

        private String userName;
        private Identity queryOwner;
        private String propertyName;
        private String catalogName;
        private CatalogSchemaName catalogSchemaName;
        private String newSchemaName;
        private TrinoPrincipal principal;
        private CatalogSchemaTableName catalogSchemaTableName;
        private Map<String, Object> properties;
        private CatalogSchemaTableName newCatalogSchemaTableName;
        private SchemaTableName schemaTableName;
        private String column;
        private Set<String> columns;

        public Builder(Operation operation) {
            this.operation = operation;
        }

        public Builder resource(OpaQueryInputResource resource) {
            this.resource = resource;
            return this;
        }

//        public Builder userName(String userName) {
//            this.userName = userName;
//            return this;
//        }
//
//        public Builder queryOwner(Identity queryOwner) {
//            this.queryOwner = queryOwner;
//            return this;
//        }
//
//        public Builder propertyName(String propertyName) {
//            this.propertyName = propertyName;
//            return this;
//        }
//
//        public Builder catalogName(String catalogName) {
//            this.catalogName = catalogName;
//            return this;
//        }
//
//        public Builder catalogSchemaName(CatalogSchemaName catalogSchemaName) {
//            this.catalogSchemaName = catalogSchemaName;
//            return this;
//        }
//
//        public Builder newSchemaName(String newSchemaName) {
//            this.newSchemaName = newSchemaName;
//            return this;
//        }
//
//        public Builder principal(TrinoPrincipal principal) {
//            this.principal = principal;
//            return this;
//        }
//
//        public Builder catalogSchemaTableName(CatalogSchemaTableName catalogSchemaTableName) {
//            this.catalogSchemaTableName = catalogSchemaTableName;
//            return this;
//        }
//
//        public Builder properties(Map<String, Object> properties) {
//            this.properties = properties;
//            return this;
//        }
//
//        public Builder properties_opt(Map<String, Optional<Object>> properties) {
//            this.properties = properties
//                    .entrySet()
//                    .stream()
//                    .collect(Collectors.toMap(entry -> entry.getKey(), entry -> entry.getValue().toString()));;
//            return this;
//        }
//
//        public Builder newCatalogSchemaTableName(CatalogSchemaTableName newTable) {
//            this.newCatalogSchemaTableName = newTable;
//            return this;
//        }
//
//        public Builder schemaTableName(SchemaTableName schemaTableName) {
//            this.schemaTableName = schemaTableName;
//            return this;
//        }
//
//        public Builder column(String column) {
//            this.column = column;
//            return this;
//        }
//
//        public Builder columns(Set<String> columns) {
//            this.columns = columns;
//            return this;
//        }

        public OpaQueryInputAction build() {
            OpaQueryInputAction action = new OpaQueryInputAction(this);
            return action;
        }
    }

}
