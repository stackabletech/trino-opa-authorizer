package trino

can_execute_query = true

can_access_catalog = true

can_access_schema = true

can_access_table = true

can_access_column = true

can_show_schemas = true

can_show_tables = true

default can_select_from_columns = false

can_select_from_columns {
	input.request.table.catalog == "system"
	input.request.table.schema == "information_schema"
	input.request.table.table == {"tables", "schemata"}[_]
}

can_view_query_owned_by = true
