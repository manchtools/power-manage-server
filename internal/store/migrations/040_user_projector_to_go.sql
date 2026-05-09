-- Replace project_user_event() with a no-op stub. The actual
-- projection logic now lives in projectors.UserListener (Go,
-- post-commit). The shared project_event() dispatcher trigger still
-- PERFORMs project_user_event(NEW) for every user-stream event;
-- the no-op stub keeps that dispatch quiet (no
-- plpgsql_projection_errors entries) until the Phase 2 cleanup
-- migration drops every still-PL/pgSQL WHEN clause from the
-- dispatcher.
--
-- This is the LAST Phase 2 port under tracker #136. After this lands,
-- every domain projector lives in Go and the next migration can drop
-- project_event() and the dispatcher trigger entirely.
--
-- Behavioural delta:
--   - Before: PL/pgSQL projector ran inside the AppendEvent
--     transaction. The sixteen event types (Created, ProfileUpdated,
--     EmailChanged, PasswordChanged, RoleChanged, SessionInvalidated,
--     Disabled, Enabled, LoggedIn, Deleted, SshKeyAdded, SshKeyRemoved,
--     SshSettingsUpdated, LinuxUsernameChanged, SystemActionLinked,
--     ProvisioningSettingsUpdated) and the UserDeleted cascade on
--     identity_links_projection were atomic with the event commit.
--   - After: Go listener fires post-commit. The multi-write event
--     (UserDeleted, with its identity_links wipe) wraps its writes
--     in store.WithTx so the cascade stays atomic with itself, but
--     not with the event commit. The handler's read-after-write
--     paths (CreateUser / DisableUser / etc. reading back from
--     users_projection) still see the projection because
--     fireListeners is synchronous — the listener has already run by
--     the time AppendEvent returns.
--
-- Tightening: every UPDATE on users_projection now carries an
-- explicit `WHERE projection_version < $N` guard, rejecting stale
-- reconciler replays. The PL/pgSQL projector stamped
-- projection_version without a guard.
--
-- Asymmetric-guard discipline (per the role + identity_provider +
-- action_set + assignment + user_group + device_group +
-- compliance_policy + compliance + action+definition + execution +
-- device ports): the guarded SoftDelete uses :execrows, and the
-- listener short-circuits the cascade (identity_links wipe) when
-- n == 0 — otherwise a stale UserDeleted re-applied later would
-- silently nuke a freshly-restored user's identity links.
--
-- Session-version monotonicity: PasswordChanged, SessionInvalidated,
-- and Disabled all bump session_version. The bump is paired with the
-- other column writes inside ONE guarded UPDATE — a stale Disable
-- replayed after a re-Enable fails the projection_version guard
-- outright (n == 0), so neither disabled NOR session_version regress
-- to the stale value. session_version stays monotonic by construction.
--
-- See manchtools/power-manage-server#136. LAST Phase 2 port under
-- tracker #107's projector-migration pattern.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION project_user_event(event events) RETURNS void AS $$
BEGIN
    -- No-op: ported to projectors.UserListener. See migration
    -- comment + the listener wiring in cmd/control/main.go via
    -- projectors.WireAll.
    NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd


-- +goose Down

-- Restore the PL/pgSQL projector verbatim from migration 007 (the
-- last definition before this port — UserSystemActionLinked extended
-- to handle system_tty_action_id, the body that was in place when
-- this port ran).

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
                system_tty_action_id = CASE
                    WHEN event.data->>'field' = 'system_tty_action_id' THEN COALESCE(event.data->>'action_id', '')
                    ELSE system_tty_action_id
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
