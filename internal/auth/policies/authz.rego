package authz

import rego.v1

# Default deny
default allow := false

# ============================================================================
# USER ACCESS (permission-based)
# ============================================================================

# Unrestricted permission match
allow if {
    input.action in input.permissions
}

# Self-scoped: resource belongs to the requesting user
allow if {
    perm := concat(":", [input.action, "self"])
    perm in input.permissions
    input.resource_id == input.subject_id
}

# Self-scoped without resource (creation actions) — handler enforces restriction
allow if {
    perm := concat(":", [input.action, "self"])
    perm in input.permissions
    not input.resource_id
}

# Assigned-scope: SQL-level filtering handles actual data check
allow if {
    perm := concat(":", [input.action, "assigned"])
    perm in input.permissions
}

# ============================================================================
# DEVICE ACCESS (unchanged)
# ============================================================================

# Devices can only view themselves
allow if {
    input.role == "device"
    input.action == "GetDevice"
    input.resource_id == input.subject_id
}

# Devices can view definitions (needed to execute actions)
allow if {
    input.role == "device"
    input.action in {"ListDefinitions", "GetDefinition"}
}

# Devices can view their own executions
allow if {
    input.role == "device"
    input.action in {"ListExecutions", "GetExecution"}
    input.device_id == input.subject_id
}

# Devices can send heartbeats and status updates
allow if {
    input.role == "device"
    input.action in {"Heartbeat", "UpdateStatus"}
}
