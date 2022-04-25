package trino

import future.keywords.in

default allow = false

allow {
	is_admin
}

allow {
	is_bob
	can_be_accessed_by_bob
}

is_admin() {
	input.context.identity.user == "admin"
}

is_bob() {
	input.context.identity.user == "bob"
}

can_be_accessed_by_bob() {
    input.action.operation in ["ImpersonateUser", "FilterCatalogs", "AccessCatalog", "ExecuteQuery"]
}