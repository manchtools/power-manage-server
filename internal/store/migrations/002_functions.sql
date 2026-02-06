-- +goose Up
-- +goose StatementBegin

-- ============================================================================
-- SECTION 1: SESSION CONTEXT HELPERS
-- ============================================================================

CREATE OR REPLACE FUNCTION set_session_context(p_user_id TEXT, p_role TEXT) RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_user_id', COALESCE(p_user_id, ''), TRUE);
    PERFORM set_config('app.current_role', COALESCE(p_role, ''), TRUE);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION current_user_id() RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', TRUE), '');
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION current_user_role() RETURNS TEXT AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_role', TRUE), '');
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION is_admin() RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_user_role() = 'admin';
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- SECTION 2: ULID GENERATION
-- ============================================================================

CREATE OR REPLACE FUNCTION generate_ulid() RETURNS TEXT AS $$
DECLARE
    timestamp_ms BIGINT;
    random_bytes BYTEA;
    ulid TEXT := '';
    alphabet TEXT := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    i INTEGER;
    val BIGINT;
BEGIN
    timestamp_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;

    FOR i IN REVERSE 9..0 LOOP
        ulid := ulid || substr(alphabet, (timestamp_ms % 32)::INTEGER + 1, 1);
        timestamp_ms := timestamp_ms / 32;
    END LOOP;

    ulid := reverse(ulid);

    random_bytes := gen_random_bytes(10);

    val := 0;
    FOR i IN 0..9 LOOP
        val := (val * 256) + get_byte(random_bytes, i);
        IF (i + 1) % 5 = 0 THEN
            FOR j IN REVERSE 7..0 LOOP
                ulid := ulid || substr(alphabet, ((val >> (j * 5)) & 31)::INTEGER + 1, 1);
            END LOOP;
            val := 0;
        END IF;
    END LOOP;

    RETURN ulid;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 3: PROJECTOR FUNCTIONS
-- ============================================================================

-- ---------- USER PROJECTOR ----------

CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                event.data->>'password_hash',
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num
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
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserRoleChanged' THEN
            UPDATE users_projection
            SET role = event.data->>'role',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserDisabled' THEN
            UPDATE users_projection
            SET disabled = TRUE,
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

-- ---------- TOKEN PROJECTOR ----------

CREATE OR REPLACE FUNCTION project_token_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'TokenCreated' THEN
            INSERT INTO tokens_projection (
                id, value_hash, name, one_time, max_uses, expires_at,
                created_at, created_by, owner_id, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'value_hash',
                COALESCE(event.data->>'name', ''),
                COALESCE((event.data->>'one_time')::BOOLEAN, FALSE),
                COALESCE((event.data->>'max_uses')::INTEGER, 0),
                CASE WHEN event.data->>'expires_at' IS NOT NULL
                     THEN (event.data->>'expires_at')::TIMESTAMPTZ
                     ELSE NULL END,
                event.occurred_at,
                event.actor_id,
                COALESCE(event.data->>'owner_id', event.actor_id),
                event.sequence_num
            );

        WHEN 'TokenUsed' THEN
            UPDATE tokens_projection
            SET current_uses = current_uses + 1,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenDisabled' THEN
            UPDATE tokens_projection
            SET disabled = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenEnabled' THEN
            UPDATE tokens_projection
            SET disabled = FALSE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'TokenDeleted' THEN
            UPDATE tokens_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- DEVICE PROJECTOR ----------
-- Combined from migrations 002 + 022: includes DeviceAssigned/Unassigned AND sync intervals.

CREATE OR REPLACE FUNCTION project_device_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DeviceRegistered' THEN
            INSERT INTO devices_projection (
                id, hostname, cert_fingerprint, cert_not_after,
                registered_at, last_seen_at, registration_token_id,
                labels, projection_version
            ) VALUES (
                event.stream_id,
                COALESCE(event.data->>'hostname', ''),
                event.data->>'cert_fingerprint',
                CASE WHEN event.data->>'cert_not_after' IS NOT NULL
                     THEN (event.data->>'cert_not_after')::TIMESTAMPTZ
                     ELSE NULL END,
                event.occurred_at,
                event.occurred_at,
                event.data->>'registration_token_id',
                COALESCE(event.data->'labels', '{}'),
                event.sequence_num
            )
            ON CONFLICT (id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                cert_fingerprint = EXCLUDED.cert_fingerprint,
                cert_not_after = EXCLUDED.cert_not_after,
                registered_at = EXCLUDED.registered_at,
                last_seen_at = EXCLUDED.last_seen_at,
                registration_token_id = EXCLUDED.registration_token_id,
                labels = EXCLUDED.labels,
                projection_version = EXCLUDED.projection_version,
                is_deleted = FALSE;

        WHEN 'DeviceSeen' THEN
            UPDATE devices_projection
            SET last_seen_at = event.occurred_at,
                agent_version = COALESCE(event.data->>'agent_version', agent_version),
                hostname = COALESCE(NULLIF(event.data->>'hostname', ''), hostname),
                projection_version = event.sequence_num,
                is_deleted = FALSE
            WHERE id = event.stream_id;

        WHEN 'DeviceHeartbeat' THEN
            UPDATE devices_projection
            SET last_seen_at = event.occurred_at,
                agent_version = COALESCE(event.data->>'agent_version', agent_version),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceCertRenewed' THEN
            UPDATE devices_projection
            SET cert_fingerprint = event.data->>'cert_fingerprint',
                cert_not_after = CASE WHEN event.data->>'cert_not_after' IS NOT NULL
                                      THEN (event.data->>'cert_not_after')::TIMESTAMPTZ
                                      ELSE cert_not_after END,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelsUpdated' THEN
            UPDATE devices_projection
            SET labels = COALESCE(event.data->'labels', labels),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelSet' THEN
            UPDATE devices_projection
            SET labels = COALESCE(labels, '{}'::jsonb) || jsonb_build_object(event.data->>'key', event.data->>'value'),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceLabelRemoved' THEN
            UPDATE devices_projection
            SET labels = labels - (event.data->>'key'),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceDeleted' THEN
            UPDATE devices_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceAssigned' THEN
            UPDATE devices_projection
            SET assigned_user_id = event.data->>'user_id',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceUnassigned' THEN
            UPDATE devices_projection
            SET assigned_user_id = NULL,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceSyncIntervalSet' THEN
            UPDATE devices_projection
            SET sync_interval_minutes = COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- ACTION PROJECTOR ----------
-- Handles Action* events and legacy Definition* events for single-action definitions.

CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type,
                params, timeout_seconds, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        -- Legacy single-action definition events (backward compatibility)
        WHEN 'DefinitionCreated' THEN
            -- Only handle old-style definitions that have action_type
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type,
                    params, timeout_seconds, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- EXECUTION PROJECTOR ----------
-- Final version with agent timestamps, output on failed/timeout/skipped.

CREATE OR REPLACE FUNCTION project_execution_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ExecutionCreated' THEN
            INSERT INTO executions_projection (
                id, device_id, action_id, action_type, desired_state,
                params, timeout_seconds, status, created_at,
                created_by_type, created_by_id, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                COALESCE(event.data->>'action_id', event.data->>'definition_id'),
                (event.data->>'action_type')::INTEGER,
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                'pending',
                COALESCE((event.data->>'executed_at')::TIMESTAMPTZ, event.occurred_at),
                event.actor_type,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ExecutionDispatched' THEN
            UPDATE executions_projection
            SET status = 'dispatched',
                dispatched_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionStarted' THEN
            UPDATE executions_projection
            SET status = 'running',
                started_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionCompleted' THEN
            UPDATE executions_projection
            SET status = 'success',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionFailed' THEN
            UPDATE executions_projection
            SET status = 'failed',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionTimedOut' THEN
            UPDATE executions_projection
            SET status = 'timeout',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionSkipped' THEN
            UPDATE executions_projection
            SET status = 'skipped',
                completed_at = event.occurred_at,
                error = event.data->>'reason',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- ACTION SET PROJECTOR ----------

CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionSetRenamed' THEN
            UPDATE action_sets_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDescriptionUpdated' THEN
            UPDATE action_sets_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberAdded' THEN
            INSERT INTO action_set_members_projection (
                set_id, action_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (set_id, action_id) DO NOTHING;

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberRemoved' THEN
            DELETE FROM action_set_members_projection
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberReordered' THEN
            UPDATE action_set_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

        WHEN 'ActionSetDeleted' THEN
            UPDATE action_sets_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM action_set_members_projection WHERE set_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- DEFINITION (COLLECTION) PROJECTOR ----------

CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            -- Only handle new-style definition collections (no action_type field)
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
                    id, name, description, created_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    COALESCE(event.data->>'description', ''),
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE definitions_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE definitions_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberAdded' THEN
            INSERT INTO definition_members_projection (
                definition_id, action_set_id, sort_order, added_at, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'action_set_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                event.occurred_at,
                event.sequence_num
            ) ON CONFLICT (definition_id, action_set_id) DO NOTHING;

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberRemoved' THEN
            DELETE FROM definition_members_projection
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberReordered' THEN
            UPDATE definition_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

        WHEN 'DefinitionDeleted' THEN
            UPDATE definitions_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM definition_members_projection WHERE definition_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- DEVICE GROUP PROJECTOR ----------
-- Includes dynamic groups, sync intervals, manual member events.

CREATE OR REPLACE FUNCTION project_device_group_event(event events) RETURNS void AS $$
DECLARE
    is_dyn BOOLEAN;
    dyn_query TEXT;
BEGIN
    CASE event.event_type
        WHEN 'DeviceGroupCreated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            dyn_query := event.data->>'dynamic_query';

            INSERT INTO device_groups_projection (
                id, name, description, is_dynamic, dynamic_query,
                created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                is_dyn,
                dyn_query,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

            IF is_dyn THEN
                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, NOW(), 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'DeviceGroupRenamed' THEN
            UPDATE device_groups_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupDescriptionUpdated' THEN
            UPDATE device_groups_projection
            SET description = COALESCE(event.data->>'description', ''),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupQueryUpdated' THEN
            is_dyn := COALESCE((event.data->>'is_dynamic')::BOOLEAN, FALSE);
            dyn_query := event.data->>'dynamic_query';

            UPDATE device_groups_projection
            SET is_dynamic = is_dyn,
                dynamic_query = dyn_query,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            IF is_dyn THEN
                DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
                UPDATE device_groups_projection SET member_count = 0 WHERE id = event.stream_id;

                INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
                VALUES (event.stream_id, NOW(), 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
            END IF;

        WHEN 'DeviceGroupSyncIntervalSet' THEN
            UPDATE device_groups_projection
            SET sync_interval_minutes = COALESCE((event.data->>'sync_interval_minutes')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DeviceGroupMemberAdded', 'DeviceAddedToGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                INSERT INTO device_group_members_projection (
                    group_id, device_id, added_at, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'device_id',
                    event.occurred_at,
                    event.sequence_num
                ) ON CONFLICT (group_id, device_id) DO NOTHING;

                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id),
                    projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;

        WHEN 'DeviceGroupMemberRemoved', 'DeviceRemovedFromGroup' THEN
            IF NOT EXISTS (SELECT 1 FROM device_groups_projection WHERE id = event.stream_id AND is_dynamic = TRUE) THEN
                DELETE FROM device_group_members_projection
                WHERE group_id = event.stream_id AND device_id = event.data->>'device_id';

                UPDATE device_groups_projection
                SET member_count = (SELECT COUNT(*) FROM device_group_members_projection WHERE group_id = event.stream_id),
                    projection_version = event.sequence_num
                WHERE id = event.stream_id;
            END IF;

        WHEN 'DeviceGroupDeleted' THEN
            UPDATE device_groups_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM device_group_members_projection WHERE group_id = event.stream_id;
            DELETE FROM dynamic_group_evaluation_queue WHERE group_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- ASSIGNMENT PROJECTOR ----------
-- Includes sort_order and upsert for re-creation of deleted assignments.

CREATE OR REPLACE FUNCTION project_assignment_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'AssignmentCreated' THEN
            INSERT INTO assignments_projection (
                id, source_type, source_id, target_type, target_id,
                sort_order, mode, created_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'source_type',
                event.data->>'source_id',
                event.data->>'target_type',
                event.data->>'target_id',
                COALESCE((event.data->>'sort_order')::INTEGER, 0),
                COALESCE((event.data->>'mode')::INTEGER, 0),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (source_type, source_id, target_type, target_id) DO UPDATE
            SET is_deleted = FALSE,
                sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                mode = COALESCE((event.data->>'mode')::INTEGER, 0),
                projection_version = event.sequence_num;

        WHEN 'AssignmentModeChanged' THEN
            UPDATE assignments_projection
            SET mode = COALESCE((event.data->>'mode')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'AssignmentDeleted' THEN
            UPDATE assignments_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'AssignmentSortOrderChanged' THEN
            UPDATE assignments_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ---------- USER SELECTION PROJECTOR ----------

CREATE OR REPLACE FUNCTION project_user_selection_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserSelectionChanged' THEN
            INSERT INTO user_selections_projection (
                id, device_id, source_type, source_id, selected,
                updated_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'device_id',
                event.data->>'source_type',
                event.data->>'source_id',
                COALESCE((event.data->>'selected')::BOOLEAN, FALSE),
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            ) ON CONFLICT (device_id, source_type, source_id) DO UPDATE
            SET selected = COALESCE((event.data->>'selected')::BOOLEAN, FALSE),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 4: MASTER PROJECTOR WITH ERROR HANDLING
-- ============================================================================

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
            -- Route to both action projector (for legacy) and definition projector (for collections)
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

        ELSE
            NULL;
    END CASE;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 5: NOTIFICATION FUNCTION
-- ============================================================================
-- Optimized payload sizes to stay under 8KB pg_notify limit.

CREATE OR REPLACE FUNCTION notify_event() RETURNS trigger AS $$
DECLARE
    channel TEXT;
    payload TEXT;
    gateway_channel TEXT;
    gateway_payload TEXT;
BEGIN
    channel := 'events';

    -- Build notification payload based on event type
    CASE
        -- Execution status changes: send lightweight payload (no output data)
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

            -- Notify the specific device's agent channel
            IF NEW.data->>'device_id' IS NOT NULL THEN
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;

        -- Output chunks: send to device agent only, not to events channel
        WHEN NEW.event_type = 'OutputChunk' THEN
            IF NEW.data->>'device_id' IS NOT NULL THEN
                payload := json_build_object(
                    'stream_id', NEW.stream_id,
                    'event_type', NEW.event_type,
                    'data', NEW.data
                )::TEXT;
                PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
            END IF;
            -- Don't send output chunks to the events channel
            RETURN NEW;

        -- Device registration: may need gateway notification
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

            -- Send registration response to gateway if gateway_id is present
            IF NEW.data->>'gateway_id' IS NOT NULL AND NEW.data->>'connection_id' IS NOT NULL THEN
                gateway_channel := 'gateway_' || (NEW.data->>'gateway_id');
                gateway_payload := json_build_object(
                    'type', 'registration_response',
                    'connection_id', NEW.data->>'connection_id',
                    'device_id', NEW.stream_id,
                    'cert_pem', NEW.data->>'cert_pem',
                    'ca_cert_pem', NEW.data->>'ca_cert_pem'
                )::TEXT;
                PERFORM pg_notify(gateway_channel, gateway_payload);
            END IF;

        ELSE
            -- Default: send full event payload
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

    -- Notify on the events channel
    PERFORM pg_notify(channel, payload);

    -- Notify agent channel for execution events
    IF NEW.stream_type = 'execution' AND NEW.data->>'device_id' IS NOT NULL THEN
        PERFORM pg_notify('agent_' || (NEW.data->>'device_id'), payload);
    END IF;

    -- Notify UI updates channel for projectable events
    IF NEW.stream_type IN ('user', 'token', 'device', 'action', 'definition',
                            'action_set', 'device_group', 'assignment', 'execution',
                            'user_selection') THEN
        PERFORM pg_notify('ui_updates', json_build_object(
            'stream_type', NEW.stream_type,
            'stream_id', NEW.stream_id,
            'event_type', NEW.event_type
        )::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 6: DYNAMIC GROUP FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION extract_label_key(label_expr TEXT) RETURNS TEXT AS $$
DECLARE
    parts TEXT[];
BEGIN
    -- Support device.labels.key format
    IF label_expr ~* '^device\.labels\.' THEN
        RETURN substr(label_expr, 15);
    ELSIF label_expr ~* '^labels\.' THEN
        RETURN substr(label_expr, 8);
    ELSIF label_expr ~* '^device\.labels\[' THEN
        parts := regexp_matches(label_expr, '^device\.labels\[["'']?(.+?)["'']?\]$');
        IF parts IS NOT NULL THEN
            RETURN parts[1];
        END IF;
    ELSIF label_expr ~* '^labels\[' THEN
        parts := regexp_matches(label_expr, '^labels\[["'']?(.+?)["'']?\]$');
        IF parts IS NOT NULL THEN
            RETURN parts[1];
        END IF;
    END IF;
    RETURN label_expr;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION evaluate_condition(device_labels JSONB, condition TEXT) RETURNS BOOLEAN AS $$
DECLARE
    parts TEXT[];
    label_expr TEXT;
    operator TEXT;
    value TEXT;
    label_key TEXT;
    label_value TEXT;
    num_label NUMERIC;
    num_val NUMERIC;
    values_arr TEXT[];
BEGIN
    condition := trim(condition);

    IF condition = '' OR condition IS NULL THEN
        RETURN TRUE;
    END IF;

    -- Handle 'exists' operator
    IF condition ~* '^\s*(\S+)\s+exists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+exists\s*$', 'i');
        label_key := extract_label_key(parts[1]);
        RETURN device_labels ? label_key;
    END IF;

    -- Handle 'notExists' operator
    IF condition ~* '^\s*(\S+)\s+notExists\s*$' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+notExists\s*$', 'i');
        label_key := extract_label_key(parts[1]);
        RETURN NOT (device_labels ? label_key);
    END IF;

    -- Parse binary operator condition
    IF condition ~* '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+' THEN
        parts := regexp_matches(condition, '^\s*(\S+)\s+(equals|notEquals|contains|notContains|startsWith|endsWith|greaterThan|lessThan|greaterThanOrEquals|lessThanOrEquals|in|notIn)\s+[\"'']?(.+?)[\"'']?\s*$', 'i');
        label_expr := parts[1];
        operator := lower(parts[2]);
        value := parts[3];
    ELSE
        RETURN FALSE;
    END IF;

    label_key := extract_label_key(label_expr);
    IF label_key IS NULL THEN
        RETURN FALSE;
    END IF;

    label_value := device_labels ->> label_key;

    CASE operator
        WHEN 'equals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) = lower(value);

        WHEN 'notequals' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(label_value) != lower(value);

        WHEN 'contains' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE '%' || lower(value) || '%';

        WHEN 'notcontains' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            RETURN lower(label_value) NOT LIKE '%' || lower(value) || '%';

        WHEN 'startswith' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE lower(value) || '%';

        WHEN 'endswith' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            RETURN lower(label_value) LIKE '%' || lower(value);

        WHEN 'greaterthan' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label > num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value > value;
            END;

        WHEN 'lessthan' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label < num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value < value;
            END;

        WHEN 'greaterthanorequals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label >= num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value >= value;
            END;

        WHEN 'lessthanorequals' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            BEGIN
                num_label := label_value::NUMERIC;
                num_val := value::NUMERIC;
                RETURN num_label <= num_val;
            EXCEPTION WHEN OTHERS THEN
                RETURN label_value <= value;
            END;

        WHEN 'in' THEN
            IF label_value IS NULL THEN RETURN FALSE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(label_value) = ANY(values_arr);

        WHEN 'notin' THEN
            IF label_value IS NULL THEN RETURN TRUE; END IF;
            values_arr := string_to_array(value, ',');
            FOR i IN 1..array_length(values_arr, 1) LOOP
                values_arr[i] := lower(trim(values_arr[i]));
            END LOOP;
            RETURN lower(label_value) != ALL(values_arr);

        ELSE
            RETURN FALSE;
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- FIX (Issue 9): Added depth parameter with limit of 10 to prevent infinite recursion.
CREATE OR REPLACE FUNCTION evaluate_dynamic_query(
    device_labels JSONB,
    query TEXT,
    depth INTEGER DEFAULT 0
) RETURNS BOOLEAN AS $$
DECLARE
    result BOOLEAN;
    work_query TEXT;
    paren_content TEXT;
    paren_result BOOLEAN;
    pos INTEGER;
    start_pos INTEGER;
    end_pos INTEGER;
    char_at TEXT;
BEGIN
    -- Prevent infinite recursion
    IF depth > 10 THEN
        RAISE WARNING 'Dynamic query recursion depth exceeded (>10)';
        RETURN FALSE;
    END IF;

    IF query IS NULL OR trim(query) = '' THEN
        RETURN TRUE;
    END IF;

    work_query := trim(query);

    -- Resolve all parenthesized expressions (innermost first)
    LOOP
        start_pos := 0;
        end_pos := 0;

        FOR pos IN 1..length(work_query) LOOP
            char_at := substr(work_query, pos, 1);
            IF char_at = '(' THEN
                start_pos := pos;
            ELSIF char_at = ')' AND start_pos > 0 THEN
                end_pos := pos;
                EXIT;
            END IF;
        END LOOP;

        IF start_pos = 0 OR end_pos = 0 THEN
            EXIT;
        END IF;

        paren_content := substr(work_query, start_pos + 1, end_pos - start_pos - 1);
        paren_result := evaluate_dynamic_query(device_labels, paren_content, depth + 1);

        work_query := substr(work_query, 1, start_pos - 1) ||
                      CASE WHEN paren_result THEN '__TRUE__' ELSE '__FALSE__' END ||
                      substr(work_query, end_pos + 1);
    END LOOP;

    -- Handle 'not' operator (prefix)
    WHILE work_query ~* '^\s*not\s+' LOOP
        work_query := regexp_replace(work_query, '^\s*not\s+', '', 'i');
        result := NOT evaluate_dynamic_query(device_labels, work_query, depth + 1);
        RETURN result;
    END LOOP;

    -- Handle 'not' in the middle
    WHILE work_query ~* '\s+not\s+__TRUE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__TRUE__', ' __FALSE__', 'gi');
    END LOOP;
    WHILE work_query ~* '\s+not\s+__FALSE__' LOOP
        work_query := regexp_replace(work_query, '\s+not\s+__FALSE__', ' __TRUE__', 'gi');
    END LOOP;

    -- Handle 'and' operator (higher precedence)
    IF work_query ~* '\s+and\s+' THEN
        DECLARE
            parts TEXT[];
            all_true BOOLEAN := TRUE;
            part TEXT;
        BEGIN
            parts := regexp_split_to_array(work_query, '\s+and\s+', 'i');
            FOREACH part IN ARRAY parts LOOP
                IF NOT evaluate_dynamic_query(device_labels, part, depth + 1) THEN
                    all_true := FALSE;
                    EXIT;
                END IF;
            END LOOP;
            RETURN all_true;
        END;
    END IF;

    -- Handle 'or' operator
    IF work_query ~* '\s+or\s+' THEN
        DECLARE
            parts TEXT[];
            any_true BOOLEAN := FALSE;
            part TEXT;
        BEGIN
            parts := regexp_split_to_array(work_query, '\s+or\s+', 'i');
            FOREACH part IN ARRAY parts LOOP
                IF evaluate_dynamic_query(device_labels, part, depth + 1) THEN
                    any_true := TRUE;
                    EXIT;
                END IF;
            END LOOP;
            RETURN any_true;
        END;
    END IF;

    -- Handle placeholder results
    IF work_query = '__TRUE__' THEN
        RETURN TRUE;
    ELSIF work_query = '__FALSE__' THEN
        RETURN FALSE;
    END IF;

    RETURN evaluate_condition(device_labels, work_query);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Evaluate a single dynamic group and update membership.
-- FIX (Issue from 024): Uses COALESCE for empty arrays in member_count.
CREATE OR REPLACE FUNCTION evaluate_dynamic_group(group_id_param TEXT) RETURNS void AS $$
DECLARE
    group_record RECORD;
    device_record RECORD;
    query_text TEXT;
    matches BOOLEAN;
    current_members TEXT[];
    new_members TEXT[];
    members_to_add TEXT[];
    members_to_remove TEXT[];
    member_id TEXT;
BEGIN
    SELECT id, dynamic_query, is_dynamic INTO group_record
    FROM device_groups_projection
    WHERE id = group_id_param AND is_deleted = FALSE;

    IF NOT FOUND OR NOT group_record.is_dynamic THEN
        DELETE FROM dynamic_group_evaluation_queue WHERE group_id = group_id_param;
        RETURN;
    END IF;

    query_text := group_record.dynamic_query;

    SELECT array_agg(device_id) INTO current_members
    FROM device_group_members_projection
    WHERE group_id = group_id_param;

    current_members := COALESCE(current_members, ARRAY[]::TEXT[]);

    new_members := ARRAY[]::TEXT[];
    FOR device_record IN
        SELECT id, labels FROM devices_projection WHERE is_deleted = FALSE
    LOOP
        matches := evaluate_dynamic_query(device_record.labels, query_text);
        IF matches THEN
            new_members := array_append(new_members, device_record.id);
        END IF;
    END LOOP;

    members_to_add := ARRAY(
        SELECT unnest(new_members) EXCEPT SELECT unnest(current_members)
    );

    members_to_remove := ARRAY(
        SELECT unnest(current_members) EXCEPT SELECT unnest(new_members)
    );

    FOREACH member_id IN ARRAY members_to_add LOOP
        INSERT INTO device_group_members_projection (group_id, device_id, added_at, projection_version)
        VALUES (group_id_param, member_id, NOW(), 0)
        ON CONFLICT (group_id, device_id) DO NOTHING;
    END LOOP;

    FOREACH member_id IN ARRAY members_to_remove LOOP
        DELETE FROM device_group_members_projection
        WHERE group_id = group_id_param AND device_id = member_id;
    END LOOP;

    UPDATE device_groups_projection
    SET member_count = COALESCE(array_length(new_members, 1), 0)
    WHERE id = group_id_param;

    DELETE FROM dynamic_group_evaluation_queue WHERE group_id = group_id_param;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION evaluate_queued_dynamic_groups() RETURNS INTEGER AS $$
DECLARE
    evaluated_count INTEGER := 0;
    queue_record RECORD;
BEGIN
    FOR queue_record IN
        SELECT group_id FROM dynamic_group_evaluation_queue
        ORDER BY queued_at LIMIT 100
    LOOP
        PERFORM evaluate_dynamic_group(queue_record.group_id);
        evaluated_count := evaluated_count + 1;
    END LOOP;
    RETURN evaluated_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION queue_dynamic_groups_for_device(device_id_param TEXT) RETURNS void AS $$
BEGIN
    INSERT INTO dynamic_group_evaluation_queue (group_id, queued_at, reason)
    SELECT id, NOW(), 'device_' || device_id_param || '_changed'
    FROM device_groups_projection
    WHERE is_dynamic = TRUE AND is_deleted = FALSE
    ON CONFLICT (group_id) DO UPDATE SET queued_at = NOW();
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trigger_device_label_change() RETURNS trigger AS $$
BEGIN
    PERFORM queue_dynamic_groups_for_device(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION trigger_device_deleted() RETURNS trigger AS $$
BEGIN
    IF NEW.is_deleted = TRUE AND (OLD.is_deleted = FALSE OR OLD.is_deleted IS NULL) THEN
        DELETE FROM device_group_members_projection WHERE device_id = NEW.id;
        UPDATE device_groups_projection g
        SET member_count = (
            SELECT COUNT(*) FROM device_group_members_projection m WHERE m.group_id = g.id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION validate_dynamic_query(query TEXT) RETURNS TEXT AS $$
DECLARE
    test_labels JSONB := '{"test": "value"}'::JSONB;
BEGIN
    IF query IS NULL OR trim(query) = '' THEN
        RETURN NULL;
    END IF;

    IF (length(query) - length(replace(query, '(', ''))) !=
       (length(query) - length(replace(query, ')', ''))) THEN
        RETURN 'Unbalanced parentheses in query';
    END IF;

    BEGIN
        PERFORM evaluate_dynamic_query(test_labels, query);
        RETURN NULL;
    EXCEPTION WHEN OTHERS THEN
        RETURN 'Query syntax error: ' || SQLERRM;
    END;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SECTION 8: UTILITY FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION get_device_sync_interval(p_device_id TEXT) RETURNS INTEGER AS $$
DECLARE
    device_interval INTEGER;
    group_interval INTEGER;
BEGIN
    SELECT sync_interval_minutes INTO device_interval
    FROM devices_projection
    WHERE id = p_device_id AND is_deleted = FALSE;

    IF device_interval IS NOT NULL AND device_interval > 0 THEN
        RETURN device_interval;
    END IF;

    SELECT MIN(dg.sync_interval_minutes) INTO group_interval
    FROM device_groups_projection dg
    JOIN device_group_members_projection dgm ON dgm.group_id = dg.id
    WHERE dgm.device_id = p_device_id
      AND dg.is_deleted = FALSE
      AND dg.sync_interval_minutes > 0;

    IF group_interval IS NOT NULL AND group_interval > 0 THEN
        RETURN group_interval;
    END IF;

    RETURN 0;
END;
$$ LANGUAGE plpgsql STABLE;

-- Time travel function for historical state queries
CREATE OR REPLACE FUNCTION get_stream_at(
    p_stream_type TEXT,
    p_stream_id TEXT,
    p_at TIMESTAMPTZ
) RETURNS SETOF events AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM events
    WHERE stream_type = p_stream_type
      AND stream_id = p_stream_id
      AND occurred_at <= p_at
    ORDER BY stream_version;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- SECTION 9: REBUILD FUNCTIONS
-- ============================================================================

CREATE OR REPLACE FUNCTION rebuild_users_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE users_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user' ORDER BY sequence_num LOOP
        PERFORM project_user_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_tokens_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE tokens_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'token' ORDER BY sequence_num LOOP
        PERFORM project_token_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_devices_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE devices_projection CASCADE;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device' ORDER BY sequence_num LOOP
        PERFORM project_device_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_actions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE actions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type IN ('action', 'definition') ORDER BY sequence_num LOOP
        PERFORM project_action_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_executions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE executions_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'execution' ORDER BY sequence_num LOOP
        PERFORM project_execution_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_action_sets_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE action_sets_projection CASCADE;
    TRUNCATE action_set_members_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'action_set' ORDER BY sequence_num LOOP
        PERFORM project_action_set_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_definitions_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE definitions_projection CASCADE;
    TRUNCATE definition_members_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'definition' ORDER BY sequence_num LOOP
        PERFORM project_definition_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_device_groups_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE device_groups_projection CASCADE;
    TRUNCATE device_group_members_projection;
    TRUNCATE dynamic_group_evaluation_queue;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'device_group' ORDER BY sequence_num LOOP
        PERFORM project_device_group_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_assignments_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE assignments_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'assignment' ORDER BY sequence_num LOOP
        PERFORM project_assignment_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rebuild_user_selections_projection() RETURNS void AS $$
DECLARE
    event_record events;
BEGIN
    TRUNCATE user_selections_projection;
    FOR event_record IN SELECT * FROM events WHERE stream_type = 'user_selection' ORDER BY sequence_num LOOP
        PERFORM project_user_selection_event(event_record);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

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
END;
$$ LANGUAGE plpgsql;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP FUNCTION IF EXISTS rebuild_all_projections;
DROP FUNCTION IF EXISTS rebuild_user_selections_projection;
DROP FUNCTION IF EXISTS rebuild_assignments_projection;
DROP FUNCTION IF EXISTS rebuild_device_groups_projection;
DROP FUNCTION IF EXISTS rebuild_definitions_projection;
DROP FUNCTION IF EXISTS rebuild_action_sets_projection;
DROP FUNCTION IF EXISTS rebuild_executions_projection;
DROP FUNCTION IF EXISTS rebuild_actions_projection;
DROP FUNCTION IF EXISTS rebuild_devices_projection;
DROP FUNCTION IF EXISTS rebuild_tokens_projection;
DROP FUNCTION IF EXISTS rebuild_users_projection;
DROP FUNCTION IF EXISTS get_stream_at;
DROP FUNCTION IF EXISTS get_device_sync_interval;
DROP FUNCTION IF EXISTS validate_dynamic_query;
DROP FUNCTION IF EXISTS trigger_device_deleted;
DROP FUNCTION IF EXISTS trigger_device_label_change;
DROP FUNCTION IF EXISTS queue_dynamic_groups_for_device;
DROP FUNCTION IF EXISTS evaluate_queued_dynamic_groups;
DROP FUNCTION IF EXISTS evaluate_dynamic_group;
DROP FUNCTION IF EXISTS evaluate_dynamic_query;
DROP FUNCTION IF EXISTS evaluate_condition;
DROP FUNCTION IF EXISTS extract_label_key;
DROP FUNCTION IF EXISTS notify_event;
DROP FUNCTION IF EXISTS project_event;
DROP FUNCTION IF EXISTS project_user_selection_event;
DROP FUNCTION IF EXISTS project_assignment_event;
DROP FUNCTION IF EXISTS project_device_group_event;
DROP FUNCTION IF EXISTS project_definition_event;
DROP FUNCTION IF EXISTS project_action_set_event;
DROP FUNCTION IF EXISTS project_execution_event;
DROP FUNCTION IF EXISTS project_action_event;
DROP FUNCTION IF EXISTS project_device_event;
DROP FUNCTION IF EXISTS project_token_event;
DROP FUNCTION IF EXISTS project_user_event;
DROP FUNCTION IF EXISTS generate_ulid;
DROP FUNCTION IF EXISTS is_admin;
DROP FUNCTION IF EXISTS current_user_role;
DROP FUNCTION IF EXISTS current_user_id;
DROP FUNCTION IF EXISTS set_session_context;

-- +goose StatementEnd
