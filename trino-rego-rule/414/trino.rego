package trino

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow = false

group_member(group) if input.context.identity.user in data.groups[group]
user_is_group_member(user, group) if user in data.groups[group]

# Admins can do anything
allow {
    group_member("admin")
}

# Every can execute queries
allow {
    input.action == "ExecuteQuery"
}

# "impersonating" group can impersonate others, but not the admin group members
allow {
    input.action == "ImpersonateUser"
    group_member("impersonating")
    # TODO: Check if Trino puts the user superset in input.context.identity.user or input.context.principal.name
    # a la input.context.principal.name in data.groups[group]

    not user_is_group_member(input.resource.user, "admin")
}

allow {
    input.action in [
        "AccessCatalog",
        "SetCatalogSessionProperty",

        # The current opa-authorizer (as of 2023-07-07) seems to ask the same information different ways
        # see https://github.com/stackabletech/trino-opa-authorizer/blob/5d36202f96f0257762ca1d579d80805998aaea7f/src/main/java/tech/stackable/trino/opa/OpaAuthorizer.java#L231
        "FilterCatalog",
    ]

    has_catalog_permission(input.resource.catalog, "ro")
}

allow {
    input.action == "ShowSchemas"

    # If the user has access to *any* schema in the catalog, we need to grant him the permission to list *all* schemas of the catalog.
    # They can be further filtered using the filterSchemas() function
    has_permission_for_any_schema_in_catalog(input.resource.schema.catalogSchemaName.catalogName, "ro")
}

allow {
    input.action in [
        "FilterSchemas",
        "ShowCreateSchema"
    ]

    has_schema_permission(input.resource.schema.catalogSchemaName.catalogName, input.resource.schema.catalogSchemaName.schemaName, "ro")
}




grant_hierarchy := {
    "full": ["full", "rw","ro"],
    "rw": ["rw", "ro"],
    "ro": ["ro"],
}

has_catalog_permission(catalog, permission) {
    some group
    input.context.identity.user in data.groups[group]

    some grant
    permission in grant_hierarchy[grant]

    some catalog_id
    data.catalog_acls[catalog_id].catalog = catalog
    group in data.catalog_acls[catalog_id][grant]
}

has_schema_permission(catalog, schema, permission) {
    some group
    input.context.identity.user in data.groups[group]

    some grant
    permission in grant_hierarchy[grant]

    some schema_id
    data.schema_acls[schema_id].catalog = catalog
    data.schema_acls[schema_id].schema = schema
    group in data.schema_acls[schema_id][grant]
}

# Permissions granted on catalog level are inherited for schemas as well
has_schema_permission(catalog, schema, permission) {
    has_catalog_permission(catalog, permission)
}

has_permission_for_any_schema_in_catalog(catalog, permission) {
    some schema
    some schema_id
    data.schema_acls[schema_id].schema = schema
    has_schema_permission(catalog, schema, permission)
}

# We might need this explicitly, as their might be no schema within this catalog in data.schema_acls
has_permission_for_any_schema_in_catalog(catalog, permission) {
    has_catalog_permission(catalog, permission)
}
