-- +goose Up

-- ============================================================================
-- PART 2: CORE PROJECTOR FUNCTIONS
-- ============================================================================

-- ---------- ULID GENERATION ----------
-- +goose StatementBegin
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
-- +goose StatementEnd

-- ---------- USER PROJECTOR ----------
-- FINAL: merge of 020 (all event types including SSH, profile, provisioning)
-- PLUS identity link cleanup from 014 (which 020 accidentally dropped)
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'UserCreated' THEN
            INSERT INTO users_projection (
                id, email, password_hash, role, created_at, updated_at, projection_version, session_version, has_password,
                display_name, given_name, family_name, preferred_username, picture, locale,
                linux_username, linux_uid
            ) VALUES (
                event.stream_id,
                event.data->>'email',
                COALESCE(event.data->>'password_hash', ''),
                COALESCE(event.data->>'role', 'user'),
                event.occurred_at,
                event.occurred_at,
                event.sequence_num,
                0,
                COALESCE(NULLIF(event.data->>'password_hash', ''), NULL) IS NOT NULL,
                COALESCE(event.data->>'display_name', ''),
                COALESCE(event.data->>'given_name', ''),
                COALESCE(event.data->>'family_name', ''),
                COALESCE(event.data->>'preferred_username', ''),
                COALESCE(event.data->>'picture', ''),
                COALESCE(event.data->>'locale', ''),
                COALESCE(event.data->>'linux_username', ''),
                COALESCE((event.data->>'linux_uid')::INTEGER, 0)
            );

        WHEN 'UserProfileUpdated' THEN
            UPDATE users_projection
            SET display_name = COALESCE(event.data->>'display_name', ''),
                given_name = COALESCE(event.data->>'given_name', ''),
                family_name = COALESCE(event.data->>'family_name', ''),
                preferred_username = COALESCE(event.data->>'preferred_username', ''),
                picture = COALESCE(event.data->>'picture', ''),
                locale = COALESCE(event.data->>'locale', ''),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserEmailChanged' THEN
            UPDATE users_projection
            SET email = event.data->>'email',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserPasswordChanged' THEN
            UPDATE users_projection
            SET password_hash = event.data->>'password_hash',
                has_password = TRUE,
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
            -- Clean up identity links so user can be re-provisioned via SSO/SCIM
            DELETE FROM identity_links_projection WHERE user_id = event.stream_id;

            UPDATE users_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshKeyAdded' THEN
            UPDATE users_projection
            SET ssh_public_keys = ssh_public_keys || jsonb_build_array(
                jsonb_build_object(
                    'id', event.data->>'key_id',
                    'public_key', event.data->>'public_key',
                    'comment', event.data->>'comment',
                    'added_at', event.occurred_at
                )
            ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshKeyRemoved' THEN
            UPDATE users_projection
            SET ssh_public_keys = (
                SELECT COALESCE(jsonb_agg(elem), '[]'::jsonb)
                FROM jsonb_array_elements(ssh_public_keys) AS elem
                WHERE elem->>'id' != event.data->>'key_id'
            ),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSshSettingsUpdated' THEN
            UPDATE users_projection
            SET ssh_access_enabled = COALESCE((event.data->>'ssh_access_enabled')::BOOLEAN, ssh_access_enabled),
                ssh_allow_pubkey = COALESCE((event.data->>'ssh_allow_pubkey')::BOOLEAN, ssh_allow_pubkey),
                ssh_allow_password = COALESCE((event.data->>'ssh_allow_password')::BOOLEAN, ssh_allow_password),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserLinuxUsernameChanged' THEN
            UPDATE users_projection
            SET linux_username = event.data->>'linux_username',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserSystemActionLinked' THEN
            UPDATE users_projection
            SET system_user_action_id = CASE
                    WHEN event.data->>'field' = 'system_user_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_user_action_id
                END,
                system_ssh_action_id = CASE
                    WHEN event.data->>'field' = 'system_ssh_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_ssh_action_id
                END,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'UserProvisioningSettingsUpdated' THEN
            UPDATE users_projection
            SET user_provisioning_enabled = COALESCE((event.data->>'user_provisioning_enabled')::BOOLEAN, user_provisioning_enabled),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ---------- TOKEN PROJECTOR ----------
-- FINAL from 003: adds TokenRenamed handling
-- +goose StatementBegin
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

        WHEN 'TokenRenamed' THEN
            UPDATE tokens_projection
            SET name = event.data->>'name',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

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
-- +goose StatementEnd

-- ---------- DEVICE PROJECTOR ----------
-- FINAL from 026: multi-user assignment support with junction tables
-- +goose StatementBegin
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

            -- Auto-assign device to token owner if present
            IF event.data->>'assigned_user_id' IS NOT NULL THEN
                INSERT INTO device_assigned_users_projection (device_id, user_id, assigned_at, assigned_by, projection_version)
                VALUES (event.stream_id, event.data->>'assigned_user_id', event.occurred_at, event.actor_id, event.sequence_num)
                ON CONFLICT (device_id, user_id) DO NOTHING;
            END IF;

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

            -- Clean up assignments when device is deleted
            DELETE FROM device_assigned_users_projection WHERE device_id = event.stream_id;
            DELETE FROM device_assigned_groups_projection WHERE device_id = event.stream_id;

        WHEN 'DeviceAssigned' THEN
            INSERT INTO device_assigned_users_projection (device_id, user_id, assigned_at, assigned_by, projection_version)
            VALUES (event.stream_id, event.data->>'user_id', event.occurred_at, event.actor_id, event.sequence_num)
            ON CONFLICT (device_id, user_id) DO NOTHING;

        WHEN 'DeviceUnassigned' THEN
            DELETE FROM device_assigned_users_projection
            WHERE device_id = event.stream_id AND user_id = event.data->>'user_id';

        WHEN 'DeviceGroupAssigned' THEN
            INSERT INTO device_assigned_groups_projection (device_id, group_id, assigned_at, assigned_by, projection_version)
            VALUES (event.stream_id, event.data->>'group_id', event.occurred_at, event.actor_id, event.sequence_num)
            ON CONFLICT (device_id, group_id) DO NOTHING;

        WHEN 'DeviceGroupUnassigned' THEN
            DELETE FROM device_assigned_groups_projection
            WHERE device_id = event.stream_id AND group_id = event.data->>'group_id';

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
-- +goose StatementEnd

-- ---------- ACTION PROJECTOR ----------
-- FINAL from 028: includes is_system, updated_at, and compliance cleanup on ActionDeleted
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_event(event events) RETURNS void AS $$
DECLARE
    v_device_id TEXT;
    v_affected_policies TEXT[];
BEGIN
    CASE event.event_type
        WHEN 'ActionCreated' THEN
            INSERT INTO actions_projection (
                id, name, description, action_type, desired_state,
                params, timeout_seconds, created_at, updated_at, created_by, projection_version,
                is_system, schedule
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                event.data->>'description',
                COALESCE((event.data->>'action_type')::INTEGER, 0),
                COALESCE((event.data->>'desired_state')::INTEGER, 0),
                COALESCE(event.data->'params', '{}'),
                COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                event.occurred_at,
                event.occurred_at,
                event.actor_id,
                event.sequence_num,
                COALESCE((event.data->>'is_system')::BOOLEAN, FALSE),
                event.data->'schedule'
            );

        WHEN 'ActionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Cascade rename to compliance policy rules that reference this action.
            UPDATE compliance_policy_rules_projection
            SET action_name = event.data->>'name'
            WHERE action_id = event.stream_id;

        WHEN 'ActionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionParamsUpdated' THEN
            UPDATE actions_projection
            SET params = COALESCE(event.data->'params', params),
                timeout_seconds = COALESCE((event.data->>'timeout_seconds')::INTEGER, timeout_seconds),
                desired_state = COALESCE((event.data->>'desired_state')::INTEGER, desired_state),
                schedule = COALESCE(event.data->'schedule', schedule),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionDeleted' THEN
            UPDATE actions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            UPDATE action_sets_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT set_id FROM action_set_members_projection WHERE action_id = event.stream_id
            );

            DELETE FROM action_set_members_projection WHERE action_id = event.stream_id;

            -- Clean up compliance data for this action.
            -- Collect affected policy IDs before deleting rules.
            SELECT ARRAY_AGG(DISTINCT policy_id)
            INTO v_affected_policies
            FROM compliance_policy_rules_projection
            WHERE action_id = event.stream_id;

            IF v_affected_policies IS NOT NULL THEN
                UPDATE compliance_policies_projection
                SET rule_count = rule_count - 1
                WHERE id = ANY(v_affected_policies);

                DELETE FROM compliance_policy_rules_projection WHERE action_id = event.stream_id;
                DELETE FROM compliance_policy_evaluation_projection WHERE action_id = event.stream_id;
                DELETE FROM compliance_results_projection WHERE action_id = event.stream_id;

                -- Re-evaluate compliance for all devices affected by these policies
                FOR v_device_id IN
                    SELECT DISTINCT a.target_id
                    FROM assignments_projection a
                    WHERE a.source_type = 'compliance_policy'
                      AND a.source_id = ANY(v_affected_policies)
                      AND a.target_type = 'device'
                      AND a.is_deleted = FALSE
                    UNION
                    SELECT DISTINCT dgm.device_id
                    FROM assignments_projection a
                    JOIN device_group_members_projection dgm ON dgm.group_id = a.target_id
                    WHERE a.source_type = 'compliance_policy'
                      AND a.source_id = ANY(v_affected_policies)
                      AND a.target_type = 'device_group'
                      AND a.is_deleted = FALSE
                LOOP
                    PERFORM evaluate_device_compliance_policies(v_device_id);
                END LOOP;
            END IF;

        WHEN 'DefinitionCreated' THEN
            IF event.data ? 'action_type' THEN
                INSERT INTO actions_projection (
                    id, name, description, action_type, desired_state,
                    params, timeout_seconds, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    event.data->>'description',
                    COALESCE((event.data->>'action_type')::INTEGER, 0),
                    COALESCE((event.data->>'desired_state')::INTEGER, 0),
                    COALESCE(event.data->'params', '{}'),
                    COALESCE((event.data->>'timeout_seconds')::INTEGER, 300),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE actions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE actions_projection
            SET description = event.data->>'description',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE actions_projection
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

-- ---------- EXECUTION PROJECTOR ----------
-- FINAL from 017: includes compliance fields on ExecutionCompleted/ExecutionFailed
-- +goose StatementBegin
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
                changed = COALESCE((event.data->>'changed')::BOOLEAN, TRUE),
                compliant = COALESCE((event.data->>'compliant')::BOOLEAN, FALSE),
                detection_output = event.data->'detection_output',
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ExecutionFailed' THEN
            UPDATE executions_projection
            SET status = 'failed',
                completed_at = COALESCE((event.data->>'completed_at')::TIMESTAMPTZ, event.occurred_at),
                error = event.data->>'error',
                output = event.data->'output',
                duration_ms = (event.data->>'duration_ms')::BIGINT,
                changed = COALESCE((event.data->>'changed')::BOOLEAN, TRUE),
                compliant = COALESCE((event.data->>'compliant')::BOOLEAN, FALSE),
                detection_output = event.data->'detection_output',
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
-- +goose StatementEnd

-- ---------- ACTION SET PROJECTOR ----------
-- FINAL from 025: includes updated_at on all mutating events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_action_set_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'ActionSetCreated' THEN
            INSERT INTO action_sets_projection (
                id, name, description, created_at, updated_at, created_by, projection_version
            ) VALUES (
                event.stream_id,
                event.data->>'name',
                COALESCE(event.data->>'description', ''),
                event.occurred_at,
                event.occurred_at,
                event.actor_id,
                event.sequence_num
            );

        WHEN 'ActionSetRenamed' THEN
            UPDATE action_sets_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDescriptionUpdated' THEN
            UPDATE action_sets_projection
            SET description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
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
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberRemoved' THEN
            DELETE FROM action_set_members_projection
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET member_count = (SELECT COUNT(*) FROM action_set_members_projection WHERE set_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetMemberReordered' THEN
            UPDATE action_set_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE set_id = event.stream_id AND action_id = event.data->>'action_id';

            UPDATE action_sets_projection
            SET updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'ActionSetDeleted' THEN
            UPDATE action_sets_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM action_set_members_projection WHERE set_id = event.stream_id;

            UPDATE definitions_projection
            SET member_count = member_count - 1
            WHERE id IN (
                SELECT definition_id FROM definition_members_projection WHERE action_set_id = event.stream_id
            );

            DELETE FROM definition_members_projection WHERE action_set_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ---------- DEFINITION (COLLECTION) PROJECTOR ----------
-- FINAL from 025: includes updated_at on all mutating events
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_definition_event(event events) RETURNS void AS $$
BEGIN
    CASE event.event_type
        WHEN 'DefinitionCreated' THEN
            IF NOT (event.data ? 'action_type') THEN
                INSERT INTO definitions_projection (
                    id, name, description, created_at, updated_at, created_by, projection_version
                ) VALUES (
                    event.stream_id,
                    event.data->>'name',
                    COALESCE(event.data->>'description', ''),
                    event.occurred_at,
                    event.occurred_at,
                    event.actor_id,
                    event.sequence_num
                );
            END IF;

        WHEN 'DefinitionRenamed' THEN
            UPDATE definitions_projection
            SET name = event.data->>'name',
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDescriptionUpdated' THEN
            UPDATE definitions_projection
            SET description = COALESCE(event.data->>'description', ''),
                updated_at = event.occurred_at,
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
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberRemoved' THEN
            DELETE FROM definition_members_projection
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET member_count = (SELECT COUNT(*) FROM definition_members_projection WHERE definition_id = event.stream_id),
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionMemberReordered' THEN
            UPDATE definition_members_projection
            SET sort_order = COALESCE((event.data->>'sort_order')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE definition_id = event.stream_id AND action_set_id = event.data->>'action_set_id';

            UPDATE definitions_projection
            SET updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'DefinitionDeleted' THEN
            UPDATE definitions_projection
            SET is_deleted = TRUE,
                updated_at = event.occurred_at,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            DELETE FROM definition_members_projection WHERE definition_id = event.stream_id;

        ELSE
            NULL;
    END CASE;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ---------- DEVICE GROUP PROJECTOR ----------
-- FINAL from 001: unchanged through all migrations
-- +goose StatementBegin
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
                VALUES (event.stream_id, clock_timestamp(), 'group_created')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
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
                VALUES (event.stream_id, clock_timestamp(), 'query_updated')
                ON CONFLICT (group_id) DO UPDATE SET queued_at = clock_timestamp();
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
-- +goose StatementEnd

-- ---------- ASSIGNMENT PROJECTOR ----------
-- FINAL from 001: updated to trigger compliance evaluation on policy assignment changes
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_assignment_event(event events) RETURNS void AS $$
DECLARE
    v_source_type TEXT;
    v_source_id TEXT;
    v_target_type TEXT;
    v_target_id TEXT;
    v_device_id TEXT;
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

            -- Trigger compliance evaluation when a compliance policy is assigned
            IF event.data->>'source_type' = 'compliance_policy' THEN
                IF event.data->>'target_type' = 'device' THEN
                    PERFORM evaluate_device_compliance_policies(event.data->>'target_id');
                ELSIF event.data->>'target_type' = 'device_group' THEN
                    FOR v_device_id IN
                        SELECT device_id FROM device_group_members_projection
                        WHERE group_id = event.data->>'target_id'
                    LOOP
                        PERFORM evaluate_device_compliance_policies(v_device_id);
                    END LOOP;
                END IF;
            END IF;

        WHEN 'AssignmentModeChanged' THEN
            UPDATE assignments_projection
            SET mode = COALESCE((event.data->>'mode')::INTEGER, 0),
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

        WHEN 'AssignmentDeleted' THEN
            -- Look up assignment details before soft-deleting (event data is empty)
            SELECT source_type, source_id, target_type, target_id
            INTO v_source_type, v_source_id, v_target_type, v_target_id
            FROM assignments_projection
            WHERE id = event.stream_id;

            UPDATE assignments_projection
            SET is_deleted = TRUE,
                projection_version = event.sequence_num
            WHERE id = event.stream_id;

            -- Re-evaluate compliance when a compliance policy is unassigned
            IF v_source_type = 'compliance_policy' THEN
                IF v_target_type = 'device' THEN
                    -- Clean up evaluation entries for this policy on this device
                    DELETE FROM compliance_policy_evaluation_projection
                    WHERE device_id = v_target_id AND policy_id = v_source_id;
                    PERFORM evaluate_device_compliance_policies(v_target_id);
                ELSIF v_target_type = 'device_group' THEN
                    FOR v_device_id IN
                        SELECT device_id FROM device_group_members_projection
                        WHERE group_id = v_target_id
                    LOOP
                        DELETE FROM compliance_policy_evaluation_projection
                        WHERE device_id = v_device_id AND policy_id = v_source_id;
                        PERFORM evaluate_device_compliance_policies(v_device_id);
                    END LOOP;
                END IF;
            END IF;

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
-- +goose StatementEnd

-- ---------- USER SELECTION PROJECTOR ----------
-- FINAL from 001: unchanged
-- +goose StatementBegin
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
-- +goose StatementEnd

-- +goose Down
-- Full teardown is handled by Part 5 down migration.
-- This stub exists for goose compatibility.
