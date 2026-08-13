package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Search documents are derived application state. The audit primitive calls
// this after the domain callback and before commit, so an owning-row mutation
// and its searchable form cannot diverge.
type searchTouch struct {
	resourceType string
	resourceID   string
}

func refreshSearchDocumentsForEffects(ctx context.Context, tx *sql.Tx, effects []AuditEffect, touches []searchTouch) error {
	seen := make(map[string]struct{}, len(effects)+len(touches))
	refresh := func(resourceType, resourceID string) error {
		if resourceID == "" {
			return fmt.Errorf("refresh search document: empty %s resource id", resourceType)
		}
		scope := searchScopeForResource(resourceType)
		if scope == "" {
			return fmt.Errorf("refresh search document: unknown resource type %q", resourceType)
		}
		key := scope + "\x00" + resourceID
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		return refreshSearchDocument(ctx, tx, scope, resourceID)
	}
	for _, effect := range effects {
		scope := searchScopeForResource(effect.ResourceType)
		if scope == "" {
			continue
		}
		if err := refresh(effect.ResourceType, effect.ResourceID); err != nil {
			return err
		}
	}
	for _, touch := range touches {
		if err := refresh(touch.resourceType, touch.resourceID); err != nil {
			return err
		}
	}
	return nil
}

func searchScopeForResource(resourceType string) string {
	switch resourceType {
	case "action":
		return "actions"
	case "action_set":
		return "action_sets"
	case "definition":
		return "definitions"
	case "compliance_policy":
		return "compliance_policies"
	case "device", "device_inventory":
		return "devices"
	case "device_group":
		return "device_groups"
	case "user":
		return "users"
	case "user_group":
		return "user_groups"
	case "execution":
		return "executions"
	default:
		return ""
	}
}

func refreshSearchDocument(ctx context.Context, tx *sql.Tx, scope, id string) error {
	statement, ok := searchDocumentStatements[scope]
	if !ok {
		return fmt.Errorf("refresh search document: unknown scope %q", scope)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM search_documents WHERE scope = ? AND entity_id = ?`, scope, id); err != nil {
		return fmt.Errorf("refresh %s search document: delete: %w", scope, err)
	}
	if _, err := tx.ExecContext(ctx, statement, id); err != nil {
		return fmt.Errorf("refresh %s search document: insert: %w", scope, err)
	}
	return nil
}

func rebuildSearchDocuments(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM search_documents`); err != nil {
		return fmt.Errorf("rebuild search documents: clear: %w", err)
	}
	for _, spec := range searchDocumentSpecs {
		if _, err := tx.ExecContext(ctx, searchDocumentRebuildStatements[spec.scope]); err != nil {
			return fmt.Errorf("rebuild %s search documents: %w", spec.scope, err)
		}
	}
	return nil
}

// searchDocumentSpec states one scope's projection exactly once. The
// single-entity and full-rebuild statements are derived from the same body, so
// a refresh and a rebuild cannot drift into differently shaped documents.
//
// The split exists because one dual-purpose predicate cannot serve both. A
// refresh runs inside the process-wide writer lock on every audited mutation,
// and a predicate that disables itself on an empty bind is not sargable:
// SQLite drives the outermost loop with a scan and applies the id as a residual
// filter, so the executions refresh walked every execution row of every device,
// a cost that grows without bound because executions are never pruned.
type searchDocumentSpec struct {
	scope string
	// body is the INSERT ... SELECT ... FROM ... prefix, with no WHERE clause.
	body string
	// key is the single-entity predicate. It must be a bare equality on the
	// source table's primary key and it is emitted first, because that is the
	// form measured to make SQLite seek rather than scan. search_plan_test.go
	// asserts the resulting plan against the real schema.
	key string
	// filter is the rebuild-time predicate, empty when the scope has none.
	filter string
}

func (spec searchDocumentSpec) singleEntityStatement() string {
	if spec.filter == "" {
		return spec.body + "\nWHERE " + spec.key
	}
	return spec.body + "\nWHERE " + spec.key + " AND " + spec.filter
}

func (spec searchDocumentSpec) rebuildStatement() string {
	if spec.filter == "" {
		return spec.body
	}
	return spec.body + "\nWHERE " + spec.filter
}

var searchDocumentStatements, searchDocumentRebuildStatements = buildSearchDocumentStatements()

func buildSearchDocumentStatements() (single, rebuild map[string]string) {
	single = make(map[string]string, len(searchDocumentSpecs))
	rebuild = make(map[string]string, len(searchDocumentSpecs))
	for _, spec := range searchDocumentSpecs {
		single[spec.scope] = spec.singleEntityStatement()
		rebuild[spec.scope] = spec.rebuildStatement()
	}
	return single, rebuild
}

// One registration point per scope: rebuildSearchDocuments walks this slice in
// order, and both statement maps are derived from it, so no scope can be
// refreshable without also being rebuildable.
var searchDocumentSpecs = []searchDocumentSpec{{
	scope: "actions",
	key:   "a.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, fields)
SELECT 'actions', a.id, a.name, COALESCE(a.description, ''),
       a.id || ' ' || CAST(a.action_type AS TEXT), lower(a.name),
	       json_object(
	         'type', CAST(a.action_type AS TEXT),
	         -- The actions list renders this. Omitting it left the web adapter with
	         -- no honest value and it hardcoded PRESENT, so every remove-action read
	         -- as "Install" in the list while the detail page said "Remove".
	         'desired_state', CAST(a.desired_state AS TEXT),
	         'is_compliance', CASE WHEN EXISTS (SELECT 1 FROM compliance_policy_rules r WHERE r.action_id = a.id) THEN 'true' ELSE 'false' END,
         'assigned', CASE WHEN EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action' AND x.source_id = a.id AND x.is_deleted = false) THEN 'true' ELSE 'false' END,
         'created_at', COALESCE(strftime('%s', a.created_at), '0'),
         'updated_at', COALESCE(strftime('%s', a.updated_at), '0'))
FROM actions a`,
	filter: "a.is_deleted = false",
}, {
	scope: "action_sets",
	key:   "s.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, member_count, fields)
SELECT 'action_sets', s.id, s.name, s.description,
       COALESCE((SELECT group_concat(a.name, ' ') FROM action_set_members m JOIN actions a ON a.id = m.action_id WHERE m.set_id = s.id AND a.is_deleted = false), ''),
       lower(s.name),
       (SELECT count(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id WHERE m.set_id = s.id AND a.is_deleted = false),
       json_object(
         'member_count', CAST((SELECT count(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id WHERE m.set_id = s.id AND a.is_deleted = false) AS TEXT),
         'assigned', CASE WHEN EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action_set' AND x.source_id = s.id AND x.is_deleted = false) THEN 'true' ELSE 'false' END,
         'action_names', COALESCE((SELECT group_concat(a.name, ', ') FROM action_set_members m JOIN actions a ON a.id = m.action_id WHERE m.set_id = s.id AND a.is_deleted = false), ''),
         'created_at', COALESCE(strftime('%s', s.created_at), '0'),
         'updated_at', COALESCE(strftime('%s', s.updated_at), '0'))
FROM action_sets s`,
	filter: "s.is_deleted = false",
}, {
	scope: "definitions",
	key:   "d.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, member_count, fields)
SELECT 'definitions', d.id, d.name, d.description,
       COALESCE((SELECT group_concat(
	     s.name || ' ' || COALESCE((SELECT group_concat(a.name, ' ') FROM action_set_members sm JOIN actions a ON a.id = sm.action_id WHERE sm.set_id = s.id AND a.is_deleted = false), ''),
	     ' ') FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id WHERE m.definition_id = d.id AND s.is_deleted = false), ''),
       lower(d.name),
       (SELECT count(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id WHERE m.definition_id = d.id AND s.is_deleted = false),
       json_object(
         'member_count', CAST((SELECT count(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id WHERE m.definition_id = d.id AND s.is_deleted = false) AS TEXT),
         'assigned', CASE WHEN EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'definition' AND x.source_id = d.id AND x.is_deleted = false) THEN 'true' ELSE 'false' END,
         'set_names', COALESCE((SELECT group_concat(s.name, ', ') FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id WHERE m.definition_id = d.id AND s.is_deleted = false), ''),
         'created_at', COALESCE(strftime('%s', d.created_at), '0'),
         'updated_at', COALESCE(strftime('%s', d.updated_at), '0'))
FROM definitions d`,
	filter: "d.is_deleted = false",
}, {
	scope: "compliance_policies",
	key:   "p.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, member_count, fields)
SELECT 'compliance_policies', p.id, p.name, p.description,
	       COALESCE((SELECT group_concat(a.name || ' ' || COALESCE(a.description, ''), ' ') FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id WHERE r.policy_id = p.id), ''),
       lower(p.name),
       (SELECT count(*) FROM compliance_policy_rules r WHERE r.policy_id = p.id),
       json_object(
         'rule_count', CAST((SELECT count(*) FROM compliance_policy_rules r WHERE r.policy_id = p.id) AS TEXT),
         'assigned', CASE WHEN EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'compliance_policy' AND x.source_id = p.id AND x.is_deleted = false) THEN 'true' ELSE 'false' END,
	         'action_names', COALESCE((SELECT group_concat(a.name, ', ') FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id WHERE r.policy_id = p.id), ''),
         'created_at', COALESCE(strftime('%s', p.created_at), '0'))
FROM compliance_policies p`,
	filter: "p.is_deleted = false",
}, {
	scope: "devices",
	key:   "d.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, fields)
SELECT 'devices', d.id, d.hostname, '',
	       d.id || ' ' || d.agent_version || ' ' ||
	       COALESCE((SELECT group_concat(key || '=' || value, ' ') FROM device_labels l WHERE l.device_id = d.id), '') || ' ' ||
	       COALESCE((SELECT group_concat(rows, ' ') FROM device_inventory i
	                 WHERE i.device_id = d.id AND i.table_name IN (
	                   'system_info', 'os_version', 'kernel_info', 'block_devices',
	                   'interface_details', 'interface_addresses', 'usb_devices',
	                   'pci_devices', 'memory_info'
	                 )), ''),
       lower(d.hostname),
       json_object(
         'agent_version', d.agent_version,
         'os_name', COALESCE((SELECT json_extract(rows, '$[0].name') FROM device_inventory i WHERE i.device_id = d.id AND i.table_name = 'os_version'), ''),
         'os_arch', COALESCE((SELECT json_extract(rows, '$[0].arch') FROM device_inventory i WHERE i.device_id = d.id AND i.table_name = 'os_version'), ''),
         'compliance_status', CAST(d.compliance_status AS TEXT),
         'labels', COALESCE((SELECT group_concat(key || '=' || value, ',') FROM device_labels l WHERE l.device_id = d.id), ''),
         'registered_at', COALESCE(strftime('%s', d.registered_at), '0'),
         'last_seen_at', COALESCE(strftime('%s', d.last_seen_at), '0'))
FROM devices d`,
	filter: "d.is_deleted = false",
}, {
	scope: "device_groups",
	key:   "g.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, member_count, fields)
SELECT 'device_groups', g.id, g.name, g.description, g.id, lower(g.name),
       (SELECT count(*) FROM device_group_members m WHERE m.group_id = g.id),
       json_object(
         'is_dynamic', CASE WHEN g.is_dynamic THEN 'true' ELSE 'false' END,
         'member_count', CAST((SELECT count(*) FROM device_group_members m WHERE m.group_id = g.id) AS TEXT),
         'created_at', COALESCE(strftime('%s', g.created_at), '0'))
FROM device_groups g`,
	filter: "g.is_deleted = false",
}, {
	scope: "users",
	key:   "u.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, fields)
SELECT 'users', u.id, CASE WHEN u.display_name <> '' THEN u.display_name ELSE u.email END, u.email,
       u.id || ' ' || u.given_name || ' ' || u.family_name || ' ' || u.preferred_username || ' ' || u.linux_username || ' ' ||
       COALESCE((SELECT group_concat(name, ' ') FROM (
         SELECT r.name AS name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.is_deleted = false
         UNION SELECT r.name FROM user_group_members gm JOIN user_groups g ON g.id = gm.group_id AND g.is_deleted = false JOIN user_group_roles gr ON gr.group_id = gm.group_id JOIN roles r ON r.id = gr.role_id WHERE gm.user_id = u.id AND r.is_deleted = false)), ''),
       lower(CASE WHEN u.display_name <> '' THEN u.display_name ELSE u.email END),
       json_object(
         'email', u.email, 'display_name', u.display_name, 'linux_username', u.linux_username,
         'disabled', CASE WHEN u.disabled THEN 'true' ELSE 'false' END,
         'role', COALESCE((SELECT group_concat(name, ', ') FROM (
           SELECT r.name AS name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.is_deleted = false
           UNION SELECT r.name FROM user_group_members gm JOIN user_groups g ON g.id = gm.group_id AND g.is_deleted = false JOIN user_group_roles gr ON gr.group_id = gm.group_id JOIN roles r ON r.id = gr.role_id WHERE gm.user_id = u.id AND r.is_deleted = false)), ''),
         -- The users list renders direct grants and group-inherited roles as two
         -- distinct chip clusters deduplicated by role id. The union above serves
         -- the 'role' filter and cannot say which side a name came from, so both
         -- sides ride separately, names and ids aligned by a shared aggregate
         -- ORDER BY over the canonical read's ordering.
         'role_names', COALESCE((SELECT group_concat(r.name, ', ' ORDER BY ur.grant_id) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.is_deleted = false), ''),
         'role_ids', COALESCE((SELECT group_concat(r.id, ', ' ORDER BY ur.grant_id) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.is_deleted = false), ''),
         'inherited_role_names', COALESCE((SELECT group_concat(r.name, ', ' ORDER BY r.id, g.id) FROM user_group_members gm JOIN user_groups g ON g.id = gm.group_id AND g.is_deleted = false JOIN user_group_roles gr ON gr.group_id = gm.group_id JOIN roles r ON r.id = gr.role_id WHERE gm.user_id = u.id AND r.is_deleted = false), ''),
         'inherited_role_ids', COALESCE((SELECT group_concat(r.id, ', ' ORDER BY r.id, g.id) FROM user_group_members gm JOIN user_groups g ON g.id = gm.group_id AND g.is_deleted = false JOIN user_group_roles gr ON gr.group_id = gm.group_id JOIN roles r ON r.id = gr.role_id WHERE gm.user_id = u.id AND r.is_deleted = false), ''),
         'created_at', COALESCE(strftime('%s', u.created_at), '0'),
         'last_login_at', COALESCE(strftime('%s', u.last_login_at), '0'))
FROM users u`,
	filter: "u.is_deleted = false",
}, {
	scope: "user_groups",
	key:   "g.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, member_count, fields)
SELECT 'user_groups', g.id, g.name, g.description, g.id, lower(g.name),
       (SELECT count(*) FROM user_group_members m WHERE m.group_id = g.id),
       json_object(
         'is_dynamic', CASE WHEN g.is_dynamic THEN 'true' ELSE 'false' END,
         -- Mirrors the canonical group reads: a group is SCIM-managed exactly
         -- when a scim_group_mapping row names it. The list renders this chip.
         'is_scim_managed', CASE WHEN EXISTS (SELECT 1 FROM scim_group_mapping sgm WHERE sgm.user_group_id = g.id) THEN 'true' ELSE 'false' END,
         'member_count', CAST((SELECT count(*) FROM user_group_members m WHERE m.group_id = g.id) AS TEXT),
         'created_at', COALESCE(strftime('%s', g.created_at), '0'))
FROM user_groups g`,
	filter: "g.is_deleted = false",
}, {
	scope: "executions",
	key:   "e.id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, fields)
SELECT 'executions', e.id, COALESCE(d.hostname, e.device_id), COALESCE(a.name, ''),
	   e.id || ' ' || e.device_id || ' ' || COALESCE(e.action_id, '') || ' ' || COALESCE(a.name, '') || ' ' || COALESCE(d.hostname, ''),
       COALESCE(strftime('%s', e.created_at), '0'),
       json_object(
         'device_id', e.device_id, 'action_id', COALESCE(e.action_id, ''),
         'device_hostname', COALESCE(d.hostname, ''), 'action_name', COALESCE(a.name, ''),
         'status', e.status, 'action_type', CAST(e.action_type AS TEXT),
         'desired_state', CAST(e.desired_state AS TEXT),
         'changed', CASE WHEN e.changed THEN 'true' ELSE 'false' END,
         'compliant', CASE WHEN e.compliant THEN 'true' ELSE 'false' END,
         'created_at', COALESCE(strftime('%s', e.created_at), '0'),
         'scheduled_for', COALESCE(strftime('%s', e.scheduled_for), '0'),
         'completed_at', COALESCE(strftime('%s', e.completed_at), '0'))
FROM executions e
JOIN devices d ON d.id = e.device_id
LEFT JOIN actions a ON a.id = e.action_id`,
	filter: "d.is_deleted = false",
}, {
	scope: "audit_events",
	key:   "o.operation_id = ?",
	body: `
INSERT INTO search_documents (scope, entity_id, primary_text, description, related_text, sort_text, fields)
SELECT 'audit_events', o.operation_id, o.request_descriptor, o.authorization_detail,
       o.origin || ' ' || o.operation_class || ' ' || o.actor_type || ' ' || o.result || ' ' ||
       COALESCE((SELECT group_concat(e.resource_type || ' ' || e.resource_id || ' ' || e.action, ' ') FROM audit_effects e WHERE e.operation_id = o.operation_id), ''),
       COALESCE(strftime('%s', o.occurred_at), '0'),
       json_object(
         'event_type', COALESCE((SELECT e.action FROM audit_effects e WHERE e.operation_id = o.operation_id ORDER BY e.effect_seq LIMIT 1), o.result),
         'stream_type', COALESCE((SELECT e.resource_type FROM audit_effects e WHERE e.operation_id = o.operation_id ORDER BY e.effect_seq LIMIT 1), o.operation_class),
         'stream_id', COALESCE((SELECT e.resource_id FROM audit_effects e WHERE e.operation_id = o.operation_id ORDER BY e.effect_seq LIMIT 1), o.operation_id),
         'actor_type', o.actor_type, 'actor_id', o.actor_id,
         'occurred_at', COALESCE(strftime('%s', o.occurred_at), '0'))
FROM audit_operations o`,
}}
