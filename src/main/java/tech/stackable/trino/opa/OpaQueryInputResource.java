package tech.stackable.trino.opa;

import io.trino.spi.connector.CatalogSchemaName;
import io.trino.spi.security.Identity;

public class OpaQueryInputResource {
    public enum Type {
        USER,
        SYSTEM_INFORMATION,
        QUERY,
        CATALOG,
        SCHEMA,
        TABLE,
        VIEW,
        ROLE,
        PROCEDURE,
        FUNCTION,
        SYSTEM_SESSION_PROPERTY
    }

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

    public static class CatalogSchema {
        private CatalogSchemaName catalogSchema;
        public Catalog(String name) { this.name = name; }
    }

    private Type type;
    private User user;
    private Query query;
    private SystemSessionProperty systemSessionProperty;

    private Catalog catalog;

    private OpaQueryInputResource(OpaQueryInputResource.Builder builder) {
        this.type = builder.type;
        this.user = builder.user;
        this.query = builder.query;
        this.systemSessionProperty = builder.systemSessionProperty;
        this.catalog = builder.catalog;
    }

    public static class Builder {
        private Type type;
        private User user;
        private Query query;
        private SystemSessionProperty systemSessionProperty;
        private Catalog catalog;

        public Builder(Type type) {
            this.type = type;
        }

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

        public OpaQueryInputResource build() {
            OpaQueryInputResource input = new OpaQueryInputResource(this);
            return input;
        }
    }
}
