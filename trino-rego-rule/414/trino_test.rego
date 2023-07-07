package trino

import future.keywords

# Data analysts enrich data and give the customers the ability to access it
# Customer 1 is not so advanced and has read-only access to it's data in the schema "lakehouse.customer_1"
# Customer 2 however has read-write access to it's data in the schema "lakehouse.customer_2"

# We have the following special groups:
# * admin: Can do everything
# * impersonating: Can do nothing besides impersonate other users (but not admin group members)
# * anyone: All users are automatically part of this group. This can be used to e.g. make tables public

groups := {
    "admin": ["admin"], # Special group that can do everything
    "impersonating": ["superset"], # Special group that can nothing besides impersonating others (but not admins)

    # Normal users groups
    "data-analysts": ["data-analyst-1", "data-analyst-2", "data-analyst-3"],
    "customer-1": ["customer-1-user-1", "customer-1-user-2"],
    "customer-2": ["customer-2-user-1", "customer-2-user-2"],
}

# We have the following permissions:
# * full: TBD, set catalog session property
# * rw: TBD, set catalog session property
# * ro: TBD, set catalog session property
# Having a permission on a catalog automatically grant the same permission recursively on all schemas and table within the catalog
catalog_acls := [
    {
        "catalog": "lakehouse",
        "full": ["data-analysts"],
    },
]

# We have the following permissions:
# * full: Full permission, e.g. read tables, read views, write tables, refresh materialized views, create tables, drop tables, rename table, create view, drop view, rename view, drop schema
# * rw: read tables, read views, write to tables, refresh materialized views
# * ro: read tables, read views
# Having a permission on a schema automatically grant the same permission recursively on all table within the schema
schema_acls := [
    {
        "catalog": "lakehouse",
        "schema": "customer_1",
        "ro": ["customer-1"],
    },
    {
        "catalog": "lakehouse",
        "schema": "customer_2",
        "rw": ["customer-2"],
    }
]

# We have the following permissions:
# * full: Full permission, e.g. read table/view, write to table, refresh materialized view, drop table, replace view
# * rw: read table/view, write to table, refresh materialized view
# * ro: read table/view
table_acls := [
    {
        "catalog": "lakehouse",
        "schema": "customer_1",
        "table": "public_export",
        "ro": ["anyone"],
    },
]

test_everyone_can_execute_query {
    allow with input as {"action": "ExecuteQuery", "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.schema_acls as schema_acls
    allow with input as {"action": "ExecuteQuery", "context": {"identity": {"user": "data-analyst-1"}}} with data.groups as groups with data.schema_acls as schema_acls
    allow with input as {"action": "ExecuteQuery", "context": {"identity": {"user": "data-analyst-3"}}} with data.groups as groups with data.schema_acls as schema_acls
    allow with input as {"action": "ExecuteQuery", "context": {"identity": {"user": "customer-2-user-2"}}} with data.groups as groups with data.schema_acls as schema_acls
}

test_admin_can_do_anything {
    allow with input as {"action": "ExecuteQuery", "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.schema_acls as schema_acls
    allow with input as {"action": "Anything", "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.schema_acls as schema_acls
    allow with input as {"action": "DoesNotExist", "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.schema_acls as schema_acls
}

test_superset_can_impersonate {
    allow with input as {"action": "ImpersonateUser", "resource": {"user": "customer-1-user-1"}, "context": {"identity": {"user": "superset"}}} with data.groups as groups with data.schema_acls as schema_acls
}

test_superset_can_not_impersonate_admin {
    not allow with input as {"action": "ImpersonateUser", "resource": {"user": "admin"}, "context": {"identity": {"user": "superset"}}} with data.groups as groups with data.schema_acls as schema_acls
}

test_normal_users_cant_impersonate {
    not allow with input as {"action": "ImpersonateUser", "resource": {"user": "customer-1-user-2"}, "context": {"identity": {"user": "customer-1-user-1"}}} with data.groups as groups with data.schema_acls as schema_acls
}





test_catalog_permissions {
    allow with input as {"action": "AccessCatalog", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
    allow with input as {"action": "AccessCatalog", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "data-analyst-1"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
    not allow with input as {"action": "AccessCatalog", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "customer-1-user-1"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
}

test_show_schemas {
    allow with input as {"action": "ShowSchemas", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "admin"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
    allow with input as {"action": "ShowSchemas", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "data-analyst-1"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
    not allow with input as {"action": "ShowSchemas", "resource": {"catalog": "lakehouse"}, "context": {"identity": {"user": "customer-1-user-1"}}} with data.groups as groups with data.catalog_acls as catalog_acls with data.schema_acls as schema_acls with data.table_acls as table_acls
}
