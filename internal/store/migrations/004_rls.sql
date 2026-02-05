-- +goose Up
-- +goose StatementBegin

-- ============================================================================
-- ROW-LEVEL SECURITY POLICIES
-- ============================================================================
--
-- Design:
-- - ENABLE + FORCE RLS on ALL tables (including the table owner).
-- - Every policy includes a NULL/empty role bypass. Pool connections (used by
--   triggers, system operations, and event appends) do NOT set a role, so
--   current_user_role() returns NULL. This intentionally grants full access
--   to internal operations while restricting API-level access where the
--   SessionInterceptor sets the role via set_session_context().
-- - The bypass pattern is:
--     current_user_role() IS NULL OR current_user_role() = ''
-- ============================================================================

-- ---------- EVENTS (append-only) ----------

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;

CREATE POLICY events_select ON events FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND (
        (stream_type = 'device' AND stream_id = current_user_id())
        OR (stream_type = 'execution' AND data->>'device_id' = current_user_id())
    ))
    OR (current_user_role() = 'user' AND (
        (stream_type = 'user' AND stream_id = current_user_id())
        OR actor_id = current_user_id()
    ))
);

CREATE POLICY events_insert ON events FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND (
        stream_type = 'execution'
        OR (stream_type = 'device' AND stream_id = current_user_id())
    ))
    OR (current_user_role() = 'user')
);

CREATE POLICY events_no_update ON events FOR UPDATE USING (FALSE);
CREATE POLICY events_no_delete ON events FOR DELETE USING (FALSE);

-- ---------- USERS PROJECTION ----------

ALTER TABLE users_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE users_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY users_select ON users_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND id = current_user_id())
);

CREATE POLICY users_insert ON users_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY users_update ON users_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY users_delete ON users_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- TOKENS PROJECTION ----------

ALTER TABLE tokens_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE tokens_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY tokens_select ON tokens_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND owner_id = current_user_id())
);

CREATE POLICY tokens_insert ON tokens_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND owner_id = current_user_id())
);

CREATE POLICY tokens_update ON tokens_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND owner_id = current_user_id())
);

CREATE POLICY tokens_delete ON tokens_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- DEVICES PROJECTION ----------

ALTER TABLE devices_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY devices_select ON devices_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND assigned_user_id = current_user_id())
    OR (current_user_role() = 'device' AND id = current_user_id())
);

CREATE POLICY devices_insert ON devices_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY devices_update ON devices_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND id = current_user_id())
);

CREATE POLICY devices_delete ON devices_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- ACTIONS PROJECTION ----------

ALTER TABLE actions_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY actions_select ON actions_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY actions_insert ON actions_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY actions_update ON actions_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY actions_delete ON actions_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- EXECUTIONS PROJECTION ----------

ALTER TABLE executions_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE executions_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY executions_select ON executions_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND device_id = current_user_id())
);

CREATE POLICY executions_insert ON executions_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND device_id = current_user_id())
);

CREATE POLICY executions_update ON executions_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND device_id = current_user_id())
);

CREATE POLICY executions_delete ON executions_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- ACTION SETS PROJECTION ----------

ALTER TABLE action_sets_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_sets_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY action_sets_select ON action_sets_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY action_sets_insert ON action_sets_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY action_sets_update ON action_sets_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY action_sets_delete ON action_sets_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- ACTION SET MEMBERS PROJECTION ----------

ALTER TABLE action_set_members_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_set_members_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY action_set_members_select ON action_set_members_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY action_set_members_insert ON action_set_members_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY action_set_members_update ON action_set_members_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY action_set_members_delete ON action_set_members_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

-- ---------- DEFINITIONS PROJECTION ----------

ALTER TABLE definitions_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE definitions_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY definitions_select ON definitions_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY definitions_insert ON definitions_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY definitions_update ON definitions_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY definitions_delete ON definitions_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- DEFINITION MEMBERS PROJECTION ----------

ALTER TABLE definition_members_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE definition_members_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY definition_members_select ON definition_members_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR current_user_role() = 'device'
);

CREATE POLICY definition_members_insert ON definition_members_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY definition_members_update ON definition_members_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY definition_members_delete ON definition_members_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

-- ---------- DEVICE GROUPS PROJECTION ----------

ALTER TABLE device_groups_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_groups_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY device_groups_select ON device_groups_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY device_groups_insert ON device_groups_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY device_groups_update ON device_groups_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY device_groups_delete ON device_groups_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- DEVICE GROUP MEMBERS PROJECTION ----------

ALTER TABLE device_group_members_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_group_members_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY device_group_members_select ON device_group_members_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'device' AND device_id = current_user_id())
);

CREATE POLICY device_group_members_insert ON device_group_members_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY device_group_members_update ON device_group_members_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY device_group_members_delete ON device_group_members_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

-- ---------- ASSIGNMENTS PROJECTION ----------

ALTER TABLE assignments_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE assignments_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY assignments_select ON assignments_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY assignments_insert ON assignments_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY assignments_update ON assignments_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY assignments_delete ON assignments_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- USER SELECTIONS PROJECTION ----------

ALTER TABLE user_selections_projection ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_selections_projection FORCE ROW LEVEL SECURITY;

CREATE POLICY user_selections_select ON user_selections_projection FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND device_id IN (
        SELECT id FROM devices_projection
        WHERE assigned_user_id = current_user_id() AND NOT is_deleted))
    OR (current_user_role() = 'device' AND device_id = current_user_id())
);

CREATE POLICY user_selections_insert ON user_selections_projection FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND device_id IN (
        SELECT id FROM devices_projection
        WHERE assigned_user_id = current_user_id() AND NOT is_deleted))
);

CREATE POLICY user_selections_update ON user_selections_projection FOR UPDATE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
    OR (current_user_role() = 'user' AND device_id IN (
        SELECT id FROM devices_projection
        WHERE assigned_user_id = current_user_id() AND NOT is_deleted))
);

CREATE POLICY user_selections_delete ON user_selections_projection FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- ---------- REVOKED TOKENS ----------

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY revoked_tokens_select ON revoked_tokens FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY revoked_tokens_insert ON revoked_tokens FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY revoked_tokens_no_update ON revoked_tokens FOR UPDATE USING (FALSE);

CREATE POLICY revoked_tokens_delete ON revoked_tokens FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

-- ---------- DYNAMIC GROUP EVALUATION QUEUE ----------

ALTER TABLE dynamic_group_evaluation_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE dynamic_group_evaluation_queue FORCE ROW LEVEL SECURITY;

CREATE POLICY dgeq_all ON dynamic_group_evaluation_queue FOR ALL USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

-- ---------- PROJECTION ERRORS ----------

ALTER TABLE projection_errors ENABLE ROW LEVEL SECURITY;
ALTER TABLE projection_errors FORCE ROW LEVEL SECURITY;

CREATE POLICY projection_errors_select ON projection_errors FOR SELECT USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY projection_errors_insert ON projection_errors FOR INSERT WITH CHECK (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
    OR current_user_role() = 'system'
);

CREATE POLICY projection_errors_no_update ON projection_errors FOR UPDATE USING (FALSE);

CREATE POLICY projection_errors_delete ON projection_errors FOR DELETE USING (
    current_user_role() IS NULL OR current_user_role() = ''
    OR current_user_role() = 'admin'
);

-- +goose StatementEnd

-- +goose Down

-- Drop all policies and disable RLS on all tables.

ALTER TABLE projection_errors DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS projection_errors_delete ON projection_errors;
DROP POLICY IF EXISTS projection_errors_no_update ON projection_errors;
DROP POLICY IF EXISTS projection_errors_insert ON projection_errors;
DROP POLICY IF EXISTS projection_errors_select ON projection_errors;

ALTER TABLE dynamic_group_evaluation_queue DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dgeq_all ON dynamic_group_evaluation_queue;

ALTER TABLE revoked_tokens DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS revoked_tokens_delete ON revoked_tokens;
DROP POLICY IF EXISTS revoked_tokens_no_update ON revoked_tokens;
DROP POLICY IF EXISTS revoked_tokens_insert ON revoked_tokens;
DROP POLICY IF EXISTS revoked_tokens_select ON revoked_tokens;

ALTER TABLE user_selections_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_selections_delete ON user_selections_projection;
DROP POLICY IF EXISTS user_selections_update ON user_selections_projection;
DROP POLICY IF EXISTS user_selections_insert ON user_selections_projection;
DROP POLICY IF EXISTS user_selections_select ON user_selections_projection;

ALTER TABLE assignments_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS assignments_delete ON assignments_projection;
DROP POLICY IF EXISTS assignments_update ON assignments_projection;
DROP POLICY IF EXISTS assignments_insert ON assignments_projection;
DROP POLICY IF EXISTS assignments_select ON assignments_projection;

ALTER TABLE device_group_members_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_group_members_delete ON device_group_members_projection;
DROP POLICY IF EXISTS device_group_members_update ON device_group_members_projection;
DROP POLICY IF EXISTS device_group_members_insert ON device_group_members_projection;
DROP POLICY IF EXISTS device_group_members_select ON device_group_members_projection;

ALTER TABLE device_groups_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_groups_delete ON device_groups_projection;
DROP POLICY IF EXISTS device_groups_update ON device_groups_projection;
DROP POLICY IF EXISTS device_groups_insert ON device_groups_projection;
DROP POLICY IF EXISTS device_groups_select ON device_groups_projection;

ALTER TABLE definition_members_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS definition_members_delete ON definition_members_projection;
DROP POLICY IF EXISTS definition_members_update ON definition_members_projection;
DROP POLICY IF EXISTS definition_members_insert ON definition_members_projection;
DROP POLICY IF EXISTS definition_members_select ON definition_members_projection;

ALTER TABLE definitions_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS definitions_delete ON definitions_projection;
DROP POLICY IF EXISTS definitions_update ON definitions_projection;
DROP POLICY IF EXISTS definitions_insert ON definitions_projection;
DROP POLICY IF EXISTS definitions_select ON definitions_projection;

ALTER TABLE action_set_members_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS action_set_members_delete ON action_set_members_projection;
DROP POLICY IF EXISTS action_set_members_update ON action_set_members_projection;
DROP POLICY IF EXISTS action_set_members_insert ON action_set_members_projection;
DROP POLICY IF EXISTS action_set_members_select ON action_set_members_projection;

ALTER TABLE action_sets_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS action_sets_delete ON action_sets_projection;
DROP POLICY IF EXISTS action_sets_update ON action_sets_projection;
DROP POLICY IF EXISTS action_sets_insert ON action_sets_projection;
DROP POLICY IF EXISTS action_sets_select ON action_sets_projection;

ALTER TABLE executions_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS executions_delete ON executions_projection;
DROP POLICY IF EXISTS executions_update ON executions_projection;
DROP POLICY IF EXISTS executions_insert ON executions_projection;
DROP POLICY IF EXISTS executions_select ON executions_projection;

ALTER TABLE actions_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actions_delete ON actions_projection;
DROP POLICY IF EXISTS actions_update ON actions_projection;
DROP POLICY IF EXISTS actions_insert ON actions_projection;
DROP POLICY IF EXISTS actions_select ON actions_projection;

ALTER TABLE devices_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS devices_delete ON devices_projection;
DROP POLICY IF EXISTS devices_update ON devices_projection;
DROP POLICY IF EXISTS devices_insert ON devices_projection;
DROP POLICY IF EXISTS devices_select ON devices_projection;

ALTER TABLE tokens_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tokens_delete ON tokens_projection;
DROP POLICY IF EXISTS tokens_update ON tokens_projection;
DROP POLICY IF EXISTS tokens_insert ON tokens_projection;
DROP POLICY IF EXISTS tokens_select ON tokens_projection;

ALTER TABLE users_projection DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_delete ON users_projection;
DROP POLICY IF EXISTS users_update ON users_projection;
DROP POLICY IF EXISTS users_insert ON users_projection;
DROP POLICY IF EXISTS users_select ON users_projection;

ALTER TABLE events DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS events_no_delete ON events;
DROP POLICY IF EXISTS events_no_update ON events;
DROP POLICY IF EXISTS events_insert ON events;
DROP POLICY IF EXISTS events_select ON events;
