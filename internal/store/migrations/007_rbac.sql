-- +goose Up

-- ============================================================================
-- RBAC TABLES
-- ============================================================================

CREATE TABLE roles_projection (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permissions TEXT[] NOT NULL DEFAULT '{}',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE user_roles_projection (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by TEXT NOT NULL DEFAULT '',
    projection_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_user_id ON user_roles_projection(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles_projection(role_id);

-- ============================================================================
-- ROLE PROJECTOR
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'RoleCreated' THEN
            INSERT INTO roles_projection (
                id, name, description, permissions, is_system,
                created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    '{}'::TEXT[]
                ),
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'RoleUpdated' THEN
            UPDATE roles_projection
            SET name = COALESCE(NULLIF(event.data->>'name', ''), name),
                description = COALESCE(event.data->>'description', description),
                permissions = COALESCE(
                    ARRAY(SELECT jsonb_array_elements_text(event.data->'permissions')),
                    permissions
                ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'RoleDeleted' THEN
            UPDATE roles_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Remove all user-role assignments for this role
            DELETE FROM user_roles_projection WHERE role_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- USER ROLE PROJECTOR
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_role_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserRoleAssigned' THEN
            INSERT INTO user_roles_projection (
                user_id, role_id, assigned_at, assigned_by, projection_version
            ) VALUES (
                event.data->>'user_id',
                event.data->>'role_id',
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (user_id, role_id) DO NOTHING;

        WHEN 'UserRoleRevoked' THEN
            DELETE FROM user_roles_projection
            WHERE user_id = event.data->>'user_id'
              AND role_id = event.data->>'role_id';

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- UPDATE USER PROJECTOR (add UserSessionInvalidated event type)
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                event.data->>'password_hash',
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0
            );

        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSessionInvalidated' THEN
            UPDATE users_projection
            SET session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
                session_version = session_version + 1,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEnabled' THEN
            UPDATE users_projection
            SET disabled = FALSE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserLoggedIn' THEN
            UPDATE users_projection
            SET last_login_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDeleted' THEN
            UPDATE users_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- UPDATE MASTER PROJECTOR
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_event() RETURNS trigger AS $$
BEGIN
    CASE NEW.stream_type
        WHEN 'user' THEN
            BEGIN
                PERFORM project_user_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'token' THEN
            BEGIN
                PERFORM project_token_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device' THEN
            BEGIN
                PERFORM project_device_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'action' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'definition' THEN
            BEGIN
                PERFORM project_action_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->action', SQLERRM);
            END;

            BEGIN
                PERFORM project_definition_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, 'definition->definition', SQLERRM);
            END;

        WHEN 'action_set' THEN
            BEGIN
                PERFORM project_action_set_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'device_group' THEN
            BEGIN
                PERFORM project_device_group_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'assignment' THEN
            BEGIN
                PERFORM project_assignment_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'execution' THEN
            BEGIN
                PERFORM project_execution_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_selection' THEN
            BEGIN
                PERFORM project_user_selection_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'role' THEN
            BEGIN
                PERFORM project_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        WHEN 'user_role' THEN
            BEGIN
                PERFORM project_user_role_event(NEW);
            EXCEPTION WHEN OTHERS THEN
                INSERT INTO projection_errors (event_id, event_type, stream_type, error_message)
                VALUES (NEW.id, NEW.event_type, NEW.stream_type, SQLERRM);
            END;

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- UPDATE NOTIFICATION FUNCTION (add role/user_role to UI updates)
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify_event() RETURNS trigger AS $$
DECLARE
    channel TEXT;
    payload TEXT;
BEGIN
    channel := 'events';

    CASE
        WHEN NEW.event_type IN ('ExecutionCreated', 'ExecutionDispatched', 'ExecutionStarted',
                                'ExecutionCompleted', 'ExecutionFailed', 'ExecutionTimedOut', 'ExecutionSkipped') THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'device_id', NEW.data->>'device_id',
                    'action_id', COALESCE(NEW.data->>'action_id', NEW.data->>'definition_id'),
                    'action_type', NEW.data->>'action_type',
                    'status', CASE NEW.event_type
                        WHEN 'ExecutionCreated' THEN 'pending'
                        WHEN 'ExecutionDispatched' THEN 'dispatched'
                        WHEN 'ExecutionStarted' THEN 'running'
                        WHEN 'ExecutionCompleted' THEN 'success'
                        WHEN 'ExecutionFailed' THEN 'failed'
                        WHEN 'ExecutionTimedOut' THEN 'timeout'
                        WHEN 'ExecutionSkipped' THEN 'skipped'
                    END,
                    'error', NEW.data->>'error',
                    'duration_ms', NEW.data->>'duration_ms'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

            IF NEW.data->>'device_id' IS NOT NULL THEN
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;

        WHEN NEW.event_type = 'OutputChunk' THEN
            IF NEW.data->>'device_id' IS NOT NULL THEN
                payload := json_build_object(
                    'stream_id', NEW.stream_id,
                    'event_type', NEW.event_type,
                    'data', NEW.data
                )::TEXT;
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;
            RETURN NEW;

        WHEN NEW.event_type = 'DeviceRegistered' THEN
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', json_build_object(
                    'hostname', NEW.data->>'hostname',
                    'registration_token_id', NEW.data->>'registration_token_id'
                ),
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;

        ELSE
            payload := json_build_object(
                'id', NEW.id,
                'sequence_num', NEW.sequence_num,
                'stream_type', NEW.stream_type,
                'stream_id', NEW.stream_id,
                'event_type', NEW.event_type,
                'data', NEW.data,
                'actor_type', NEW.actor_type,
                'actor_id', NEW.actor_id,
                'occurred_at', NEW.occurred_at
            )::TEXT;
    END CASE;

    PERFORM pg_notify(channel, payload);

    IF NEW.stream_type = 'execution' AND NEW.data->>'device_id' IS NOT NULL THEN
        PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
    END IF;

    IF NEW.stream_type IN ('user', 'token', 'device', 'action', 'definition',
                            'action_set', 'device_group', 'assignment', 'execution',
                            'user_selection', 'role', 'user_role') THEN
        PERFORM pg_notify('ui_updates', json_build_object(
            'stream_type', NEW.stream_type,
            'stream_id', NEW.stream_id,
            'event_type', NEW.event_type
        )::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- REBUILD FUNCTIONS
-- ============================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_roles_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE roles_projection CASCADE;
    TRUNCATE user_roles_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'role' ORDER BY sequence_num LOOP
        PERFORM project_role_event(event_record);
    END LOOP;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_role' ORDER BY sequence_num LOOP
        PERFORM project_user_role_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION rebuild_all_projections() RETURNS void AS $$
BEGIN
    PERFORM rebuild_users_projection();
    PERFORM rebuild_tokens_projection();
    PERFORM rebuild_devices_projection();
    PERFORM rebuild_actions_projection();
    PERFORM rebuild_executions_projection();
    PERFORM rebuild_action_sets_projection();
    PERFORM rebuild_definitions_projection();
    PERFORM rebuild_device_groups_projection();
    PERFORM rebuild_assignments_projection();
    PERFORM rebuild_user_selections_projection();
    PERFORM rebuild_roles_projection();
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- SEED BUILT-IN ROLES
-- ============================================================================

-- +goose StatementBegin
DO $$
DECLARE
    admin_role_id TEXT;
    user_role_id TEXT;
    admin_perms JSONB;
    user_perms JSONB;
    user_record RECORD;
BEGIN
    admin_role_id := generate_ulid();
    user_role_id := generate_ulid();

    -- Admin permissions: all base RPC names (unrestricted)
    admin_perms := '["GetCurrentUser","GetUser","ListUsers","CreateUser","UpdateUserEmail","UpdateUserPassword","SetUserDisabled","DeleteUser","ListDevices","GetDevice","SetDeviceLabel","RemoveDeviceLabel","AssignDevice","UnassignDevice","SetDeviceSyncInterval","DeleteDevice","CreateToken","GetToken","ListTokens","RenameToken","SetTokenDisabled","DeleteToken","CreateAction","GetAction","ListActions","RenameAction","UpdateActionDescription","UpdateActionParams","DeleteAction","CreateActionSet","GetActionSet","ListActionSets","RenameActionSet","UpdateActionSetDescription","DeleteActionSet","AddActionToSet","RemoveActionFromSet","ReorderActionInSet","CreateDefinition","GetDefinition","ListDefinitions","RenameDefinition","UpdateDefinitionDescription","DeleteDefinition","AddActionSetToDefinition","RemoveActionSetFromDefinition","ReorderActionSetInDefinition","CreateDeviceGroup","GetDeviceGroup","ListDeviceGroups","RenameDeviceGroup","UpdateDeviceGroupDescription","UpdateDeviceGroupQuery","DeleteDeviceGroup","AddDeviceToGroup","RemoveDeviceFromGroup","ValidateDynamicQuery","EvaluateDynamicGroup","SetDeviceGroupSyncInterval","CreateAssignment","DeleteAssignment","ListAssignments","GetDeviceAssignments","SetUserSelection","ListAvailableActions","DispatchAction","DispatchToMultiple","DispatchAssignedActions","DispatchActionSet","DispatchDefinition","DispatchToGroup","DispatchInstantAction","GetExecution","ListExecutions","ListAuditEvents","GetDeviceLpsPasswords","GetDeviceLuksKeys","CreateLuksToken","RevokeLuksDeviceKey","DispatchOSQuery","GetOSQueryResult","GetDeviceInventory","RefreshDeviceInventory","CreateRole","GetRole","ListRoles","UpdateRole","DeleteRole","AssignRoleToUser","RevokeRoleFromUser","ListPermissions"]'::JSONB;

    -- User permissions: self-service
    user_perms := '["GetCurrentUser","GetUser:self","UpdateUserEmail:self","UpdateUserPassword:self","ListDevices:assigned","GetDevice:assigned","CreateToken","SetUserSelection","ListAvailableActions"]'::JSONB;

    -- Create Admin role event
    INSERT INTO events (stream_type, stream_id, stream_version, event_type, data, actor_type, actor_id)
    VALUES (
        'role', admin_role_id, 1, 'RoleCreated',
        jsonb_build_object(
            'name', 'Admin',
            'description', 'Full administrative access',
            'permissions', admin_perms,
            'is_system', true
        ),
        'system', 'migration'
    );

    -- Create User role event
    INSERT INTO events (stream_type, stream_id, stream_version, event_type, data, actor_type, actor_id)
    VALUES (
        'role', user_role_id, 1, 'RoleCreated',
        jsonb_build_object(
            'name', 'User',
            'description', 'Standard user with self-service access',
            'permissions', user_perms,
            'is_system', true
        ),
        'system', 'migration'
    );

    -- Assign existing users to roles based on their current role column
    FOR user_record IN SELECT id, role FROM users_projection WHERE is_deleted = FALSE LOOP
        IF user_record.role = 'admin' THEN
            INSERT INTO events (stream_type, stream_id, stream_version, event_type, data, actor_type, actor_id)
            VALUES (
                'user_role', user_record.id || ':' || admin_role_id, 1, 'UserRoleAssigned',
                jsonb_build_object('user_id', user_record.id, 'role_id', admin_role_id),
                'system', 'migration'
            );
        ELSE
            INSERT INTO events (stream_type, stream_id, stream_version, event_type, data, actor_type, actor_id)
            VALUES (
                'user_role', user_record.id || ':' || user_role_id, 1, 'UserRoleAssigned',
                jsonb_build_object('user_id', user_record.id, 'role_id', user_role_id),
                'system', 'migration'
            );
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- ============================================================================
-- +goose Down
-- ============================================================================

-- +goose StatementBegin

-- Remove seeded events
DELETE FROM events WHERE stream_type IN ('role', 'user_role') AND actor_id = 'migration';

-- Drop rebuild function
DROP FUNCTION IF EXISTS rebuild_roles_projection;

-- Drop projector functions
DROP FUNCTION IF EXISTS project_user_role_event;
DROP FUNCTION IF EXISTS project_role_event;

-- Drop tables
DROP TABLE IF EXISTS user_roles_projection;
DROP TABLE IF EXISTS roles_projection;

-- Restore original project_event and notify_event (without role/user_role cases)
-- Note: full restore would replicate from 001_initial.sql; omitted for brevity.
-- Running goose down and then goose up on 001 would restore them.

-- +goose StatementEnd
