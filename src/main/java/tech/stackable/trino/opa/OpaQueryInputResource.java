package tech.stackable.trino.opa;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.security.Identity;
import io.trino.spi.security.TrinoPrincipal;

public class OpaQueryInputResource {
    private User user;
    private Query query;
    private SystemSessionProperty systemSessionProperty;
    private Catalog catalog;
    private Schema schema;

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
        public Catalog(String name) { this.name = name; }
    }

    public static class Schema {
        private CatalogSchemaName schema;
        private String newSchemaName;
        private TrinoPrincipal principal;
        private String catalogName;

        public Schema(CatalogSchemaName schema) { this.schema = schema; }

        public Schema(String catalogName) { this.catalogName = catalogName; }
        public Schema(CatalogSchemaName schema, String newSchemaName) {
            this.schema = schema;
            this.newSchemaName = newSchemaName;
        }
        public Schema(CatalogSchemaName schema, TrinoPrincipal principal) {
            this.schema = schema;
            this.principal = principal;
        }
    }


    private OpaQueryInputResource(OpaQueryInputResource.Builder builder) {
        this.user = builder.user;
        this.query = builder.query;
        this.systemSessionProperty = builder.systemSessionProperty;
        this.catalog = builder.catalog;
        this.schema = builder.schema;
    }

    public static class Builder {
        private User user;
        private Query query;
        private SystemSessionProperty systemSessionProperty;
        private Catalog catalog;
        private Schema schema;

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

        public Builder schema(Schema schema) {
            this.schema = schema;
            return this;
        }

        public OpaQueryInputResource build() {
            OpaQueryInputResource input = new OpaQueryInputResource(this);
            return input;
        }
    }
}
