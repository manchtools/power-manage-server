package authz

import rego.v1

# Default deny
default allow := false

# Roles
roles := {"admin", "user", "device"}

# ============================================================================
# ADMIN ACCESS
# ============================================================================

# Admin can do anything
allow if {
    input.role == "admin"
}

# ============================================================================
# USER MANAGEMENT
# ============================================================================

# Users can view their own profile
allow if {
    input.role == "user"
    input.action == "GetUser"
    input.resource_id == input.subject_id
}

# Users can view current user (themselves)
allow if {
    input.role == "user"
    input.action == "GetCurrentUser"
}

# Users can update their own password
allow if {
    input.role == "user"
    input.action == "UpdateUserPassword"
    input.resource_id == input.subject_id
}

# ListUsers is admin-only (no rule for users)
# CreateUser is admin-only (no rule for users)
# UpdateUserEmail is admin-only (no rule for users)
# UpdateUserRole is admin-only (no rule for users)
# SetUserDisabled is admin-only (no rule for users)
# DeleteUser is admin-only (no rule for users)

# ============================================================================
# DEVICE MANAGEMENT
# ============================================================================

# Device management is admin-only by default
# Users can list/get their assigned devices (see rule below)

# Devices can only view themselves
allow if {
    input.role == "device"
    input.action == "GetDevice"
    input.resource_id == input.subject_id
}

# Device label management is admin-only
# SetDeviceLabel is admin-only (no rule for users)
# RemoveDeviceLabel is admin-only (no rule for users)
# DeleteDevice is admin-only (no rule for users)

# AssignDevice and UnassignDevice are admin-only (implicit)

# ============================================================================
# REGISTRATION TOKENS
# ============================================================================

# Users can create their own registration tokens (for self-service device registration)
# User tokens are always one-time use with max 7-day validity (enforced by handler)
allow if {
    input.role == "user"
    input.action == "CreateToken"
}

# All other token management (Get, List, Rename, Disable, Delete) is admin-only

# Users can view their assigned devices (SQL filter enforces assignment)
allow if {
    input.role == "user"
    input.action in {"ListDevices", "GetDevice"}
}

# ============================================================================
# ACTION DEFINITIONS
# ============================================================================

# Definitions are admin-only for management
# Devices can view definitions (needed to execute actions)
allow if {
    input.role == "device"
    input.action in {"ListDefinitions", "GetDefinition"}
}

# All definition management (Create, Rename, Update, Delete) is admin-only

# ============================================================================
# ACTION DISPATCH & EXECUTION
# ============================================================================

# Dispatching actions is admin-only
# DispatchAction is admin-only (no rule for users)
# DispatchToMultiple is admin-only (no rule for users)

# Devices can view their own executions
allow if {
    input.role == "device"
    input.action in {"ListExecutions", "GetExecution"}
    input.device_id == input.subject_id
}

# ============================================================================
# USER SELECTIONS (available assignments)
# ============================================================================

# Users can manage their selections on available assignments for their devices
allow if {
    input.role == "user"
    input.action in {"SetUserSelection", "ListAvailableActions"}
}

# ============================================================================
# DEVICE HEARTBEAT & STATUS
# ============================================================================

# Devices can send heartbeats and status updates
allow if {
    input.role == "device"
    input.action in {"Heartbeat", "UpdateStatus"}
}
