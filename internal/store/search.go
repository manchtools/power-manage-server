package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidSearch means a facet, filter, sort, or page bound is outside the
// fixed PostgreSQL search contract.
var ErrInvalidSearch = errors.New("invalid search request")

// SearchDateRange narrows one allowlisted timestamp field by Unix seconds.
type SearchDateRange struct {
	Field      string
	Start, End int64
}

// SearchParams is one deterministic page within one search facet.
type SearchParams struct {
	Scope      string
	Query      string
	Offset     int32
	Limit      int32
	DateRanges []SearchDateRange
	TagFilters map[string][]string
	SortField  string
	Descending bool

	ScopeRestricted bool
	ScopeGroupIDs   []string
	AssignedUserID  *string
	OnlineSince     time.Time
}

// SearchRow is the common wire-facing shape returned by every facet.
type SearchRow struct {
	ID, Name, Description string
	MemberCount           int64
	Fields                map[string]string
}

type searchFilter struct {
	predicate string
	kind      string
}

type searchFacet struct {
	from, where, id, name, description, memberCount string
	fields, textMatch, scopeMatch                   string
	tagFilters                                      map[string]searchFilter
	dateFilters, sorts                              map[string]string
	defaultSort                                     string
}

const assignmentGroupsCTE = `assignment_groups AS (
    SELECT a.source_type, a.source_id, a.target_id AS group_id
    FROM assignments a
    WHERE a.is_deleted = FALSE AND a.target_type IN ('device_group', 'user_group')
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN devices d ON d.id = a.target_id AND d.is_deleted = FALSE
    JOIN device_group_members m ON m.device_id = d.id
    JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'device'
    UNION ALL
    SELECT a.source_type, a.source_id, m.group_id
    FROM assignments a
    JOIN users u ON u.id = a.target_id AND u.is_deleted = FALSE
    JOIN user_group_members m ON m.user_id = u.id
    JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
    WHERE a.is_deleted = FALSE AND a.target_type = 'user'
)`

var searchFacets = map[string]searchFacet{
	"actions": {
		from: "actions a", where: "a.is_deleted = FALSE AND a.is_system = FALSE",
		id: "a.id", name: "a.name", description: "COALESCE(a.description, '')", memberCount: "0::bigint",
		fields: `jsonb_build_object(
            'name', a.name, 'description', COALESCE(a.description, ''),
            'type', a.action_type::text,
            'is_compliance', (COALESCE(a.params->>'isCompliance', 'false') = 'true')::text,
            'assigned', (EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action' AND x.source_id = a.id AND x.is_deleted = FALSE))::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM a.created_at)::bigint, 0)::text,
            'updated_at', COALESCE(EXTRACT(EPOCH FROM a.updated_at)::bigint, 0)::text)`,
		textMatch: "a.search_tsv @@ pq.value OR starts_with(lower(a.id), lower(@query::text))",
		scopeMatch: `EXISTS (SELECT 1 FROM assignment_groups ag
            WHERE ag.source_type = 'action' AND ag.source_id = a.id AND ag.group_id = ANY(@scope_group_ids::text[]))
          OR EXISTS (SELECT 1 FROM action_set_members m JOIN assignment_groups ag
            ON ag.source_type = 'action_set' AND ag.source_id = m.set_id
            WHERE m.action_id = a.id AND ag.group_id = ANY(@scope_group_ids::text[]))
          OR EXISTS (SELECT 1 FROM action_set_members sm
            JOIN definition_members dm ON dm.action_set_id = sm.set_id
            JOIN assignment_groups ag ON ag.source_type = 'definition' AND ag.source_id = dm.definition_id
            WHERE sm.action_id = a.id AND ag.group_id = ANY(@scope_group_ids::text[]))
          OR EXISTS (SELECT 1 FROM compliance_policy_rules r JOIN assignment_groups ag
            ON ag.source_type = 'compliance_policy' AND ag.source_id = r.policy_id
            WHERE r.action_id = a.id AND ag.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"type":          {predicate: "a.action_type = ANY({{arg}}::integer[])", kind: "int"},
			"is_compliance": {predicate: "(COALESCE(a.params->>'isCompliance', 'false') = 'true') = ANY({{arg}}::boolean[])", kind: "bool"},
			"assigned":      {predicate: "(EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action' AND x.source_id = a.id AND x.is_deleted = FALSE)) = ANY({{arg}}::boolean[])", kind: "bool"},
		},
		dateFilters: map[string]string{"created_at": "a.created_at", "updated_at": "a.updated_at"},
		sorts:       map[string]string{"name": "a.name", "type": "a.action_type", "created_at": "a.created_at", "updated_at": "a.updated_at"},
		defaultSort: "created_at",
	},
	"action_sets": {
		from: "action_sets s", where: "s.is_deleted = FALSE",
		id: "s.id", name: "s.name", description: "s.description",
		memberCount: `(SELECT COUNT(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE WHERE m.set_id = s.id)`,
		fields: `jsonb_build_object(
            'name', s.name, 'description', s.description,
            'member_count', (SELECT COUNT(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE WHERE m.set_id = s.id)::text,
			'action_names', COALESCE((SELECT string_agg(a.name, ' ' ORDER BY m.sort_order, a.id)
				FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE
				WHERE m.set_id = s.id), ''),
            'assigned', (EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action_set' AND x.source_id = s.id AND x.is_deleted = FALSE))::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM s.created_at)::bigint, 0)::text,
            'updated_at', COALESCE(EXTRACT(EPOCH FROM s.updated_at)::bigint, 0)::text)`,
		textMatch: `s.search_tsv @@ pq.value OR starts_with(lower(s.id), lower(@query::text)) OR EXISTS (
            SELECT 1 FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE
            WHERE m.set_id = s.id AND a.search_tsv @@ pq.value)`,
		scopeMatch: `EXISTS (SELECT 1 FROM assignment_groups ag
            WHERE ag.source_type = 'action_set' AND ag.source_id = s.id AND ag.group_id = ANY(@scope_group_ids::text[]))
          OR EXISTS (SELECT 1 FROM definition_members m JOIN assignment_groups ag
            ON ag.source_type = 'definition' AND ag.source_id = m.definition_id
            WHERE m.action_set_id = s.id AND ag.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"member_count": {predicate: "(SELECT COUNT(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE WHERE m.set_id = s.id) = ANY({{arg}}::bigint[])", kind: "int64"},
			"assigned":     {predicate: "(EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'action_set' AND x.source_id = s.id AND x.is_deleted = FALSE)) = ANY({{arg}}::boolean[])", kind: "bool"},
		},
		dateFilters: map[string]string{"created_at": "s.created_at", "updated_at": "s.updated_at"},
		sorts:       map[string]string{"name": "s.name", "member_count": `(SELECT COUNT(*) FROM action_set_members m JOIN actions a ON a.id = m.action_id AND a.is_deleted = FALSE WHERE m.set_id = s.id)`, "created_at": "s.created_at", "updated_at": "s.updated_at"},
		defaultSort: "created_at",
	},
	"definitions": {
		from: "definitions d", where: "d.is_deleted = FALSE",
		id: "d.id", name: "d.name", description: "d.description",
		memberCount: `(SELECT COUNT(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE WHERE m.definition_id = d.id)`,
		fields: `jsonb_build_object(
            'name', d.name, 'description', d.description,
            'member_count', (SELECT COUNT(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE WHERE m.definition_id = d.id)::text,
			'set_names', COALESCE((SELECT string_agg(s.name, ' ' ORDER BY dm.sort_order, s.id)
				FROM definition_members dm JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
				WHERE dm.definition_id = d.id), ''),
			'action_names', COALESCE((SELECT string_agg(a.name, ' ' ORDER BY dm.sort_order, sm.sort_order, a.id)
				FROM definition_members dm JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
				JOIN action_set_members sm ON sm.set_id = s.id JOIN actions a ON a.id = sm.action_id AND a.is_deleted = FALSE
				WHERE dm.definition_id = d.id), ''),
            'assigned', (EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'definition' AND x.source_id = d.id AND x.is_deleted = FALSE))::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM d.created_at)::bigint, 0)::text,
            'updated_at', COALESCE(EXTRACT(EPOCH FROM d.updated_at)::bigint, 0)::text)`,
		textMatch: `d.search_tsv @@ pq.value OR starts_with(lower(d.id), lower(@query::text)) OR EXISTS (
            SELECT 1 FROM definition_members dm JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
            WHERE dm.definition_id = d.id AND s.search_tsv @@ pq.value)
          OR EXISTS (SELECT 1 FROM definition_members dm
            JOIN action_sets s ON s.id = dm.action_set_id AND s.is_deleted = FALSE
            JOIN action_set_members sm ON sm.set_id = s.id
            JOIN actions a ON a.id = sm.action_id AND a.is_deleted = FALSE
            WHERE dm.definition_id = d.id AND a.search_tsv @@ pq.value)`,
		scopeMatch: `EXISTS (SELECT 1 FROM assignment_groups ag
            WHERE ag.source_type = 'definition' AND ag.source_id = d.id AND ag.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"member_count": {predicate: "(SELECT COUNT(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE WHERE m.definition_id = d.id) = ANY({{arg}}::bigint[])", kind: "int64"},
			"assigned":     {predicate: "(EXISTS (SELECT 1 FROM assignments x WHERE x.source_type = 'definition' AND x.source_id = d.id AND x.is_deleted = FALSE)) = ANY({{arg}}::boolean[])", kind: "bool"},
		},
		dateFilters: map[string]string{"created_at": "d.created_at", "updated_at": "d.updated_at"},
		sorts:       map[string]string{"name": "d.name", "member_count": `(SELECT COUNT(*) FROM definition_members m JOIN action_sets s ON s.id = m.action_set_id AND s.is_deleted = FALSE WHERE m.definition_id = d.id)`, "created_at": "d.created_at", "updated_at": "d.updated_at"},
		defaultSort: "created_at",
	},
	"compliance_policies": {
		from: "compliance_policies p", where: "p.is_deleted = FALSE",
		id: "p.id", name: "p.name", description: "p.description",
		memberCount: `(SELECT COUNT(*) FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE WHERE r.policy_id = p.id)`,
		fields: `jsonb_build_object(
            'name', p.name, 'description', p.description,
			'action_names', COALESCE((SELECT string_agg(a.name, ' ' ORDER BY a.name, a.id)
				FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE
				WHERE r.policy_id = p.id), ''),
            'rule_count', (SELECT COUNT(*) FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE WHERE r.policy_id = p.id)::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM p.created_at)::bigint, 0)::text)`,
		textMatch: `p.search_tsv @@ pq.value OR starts_with(lower(p.id), lower(@query::text)) OR EXISTS (
            SELECT 1 FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE
            WHERE r.policy_id = p.id AND a.search_tsv @@ pq.value)`,
		scopeMatch: `EXISTS (SELECT 1 FROM assignment_groups ag
            WHERE ag.source_type = 'compliance_policy' AND ag.source_id = p.id AND ag.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"rule_count": {predicate: "(SELECT COUNT(*) FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE WHERE r.policy_id = p.id) = ANY({{arg}}::bigint[])", kind: "int64"},
		},
		dateFilters: map[string]string{"created_at": "p.created_at"},
		sorts:       map[string]string{"name": "p.name", "rule_count": `(SELECT COUNT(*) FROM compliance_policy_rules r JOIN actions a ON a.id = r.action_id AND a.is_deleted = FALSE WHERE r.policy_id = p.id)`, "created_at": "p.created_at"},
		defaultSort: "created_at",
	},
	"devices": {
		from: "devices d", where: `d.is_deleted = FALSE AND (@assigned_user_id::text IS NULL
          OR EXISTS (SELECT 1 FROM device_assigned_users dau WHERE dau.device_id = d.id AND dau.user_id = @assigned_user_id)
          OR EXISTS (SELECT 1 FROM device_assigned_groups dag JOIN user_group_members ugm ON ugm.group_id = dag.group_id
              JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
              WHERE dag.device_id = d.id AND ugm.user_id = @assigned_user_id))`,
		id: "d.id", name: "d.hostname", description: "''::text", memberCount: "0::bigint",
		fields: `jsonb_build_object(
            'hostname', d.hostname, 'agent_version', d.agent_version,
			'labels', COALESCE((SELECT string_agg(l.key || '=' || l.value, ' ' ORDER BY l.key, l.value)
				FROM device_labels l WHERE l.device_id = d.id), ''),
            'os_name', COALESCE((SELECT di.rows->0->>'name' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'os_version'), ''),
            'os_version', COALESCE((SELECT di.rows->0->>'version' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'os_version'), ''),
            'os_arch', COALESCE((SELECT di.rows->0->>'arch' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'os_version'), ''),
            'kernel', COALESCE((SELECT di.rows->0->>'version' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'kernel_info'), ''),
            'compliance_status', d.compliance_status::text,
            'registered_at', COALESCE(EXTRACT(EPOCH FROM d.registered_at)::bigint, 0)::text,
            'last_seen_at', COALESCE(EXTRACT(EPOCH FROM d.last_seen_at)::bigint, 0)::text)`,
		textMatch: `d.search_tsv @@ pq.value OR starts_with(lower(d.id), lower(@query::text))
          OR starts_with(lower(d.hostname), lower(@query::text))
		  OR EXISTS (SELECT 1 FROM device_labels l WHERE l.device_id = d.id
              AND to_tsvector('simple'::regconfig, l.key || ' ' || l.value) @@ pq.value)
          OR EXISTS (SELECT 1 FROM device_inventory di WHERE di.device_id = d.id
              AND to_tsvector('simple'::regconfig, di.table_name || ' ' || di.rows::text) @@ pq.value)`,
		scopeMatch: `EXISTS (SELECT 1 FROM device_group_members m JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
            WHERE m.device_id = d.id AND m.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"agent_version":     {predicate: "d.agent_version = ANY({{arg}}::text[])", kind: "text"},
			"os_name":           {predicate: "COALESCE((SELECT di.rows->0->>'name' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'os_version'), '') = ANY({{arg}}::text[])", kind: "text"},
			"os_arch":           {predicate: "COALESCE((SELECT di.rows->0->>'arch' FROM device_inventory di WHERE di.device_id = d.id AND di.table_name = 'os_version'), '') = ANY({{arg}}::text[])", kind: "text"},
			"compliance_status": {predicate: "d.compliance_status::text = ANY({{arg}}::text[])", kind: "text"},
			"status":            {predicate: "{{device_status}}", kind: "device_status"},
		},
		dateFilters: map[string]string{"registered_at": "d.registered_at", "last_seen_at": "d.last_seen_at"},
		sorts:       map[string]string{"hostname": "d.hostname", "compliance_status": "d.compliance_status", "registered_at": "d.registered_at", "last_seen_at": "d.last_seen_at"},
		defaultSort: "last_seen_at",
	},
	"users": {
		from: "users u", where: "u.is_deleted = FALSE",
		id: "u.id", name: "u.email", description: "u.display_name", memberCount: "0::bigint",
		fields: `jsonb_build_object(
            'email', u.email, 'display_name', u.display_name, 'linux_username', u.linux_username,
            'disabled', u.disabled::text,
            'role', COALESCE((SELECT string_agg(DISTINCT r.name, ',' ORDER BY r.name) FROM roles r
                WHERE r.is_deleted = FALSE AND (EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = r.id)
                  OR EXISTS (SELECT 1 FROM user_group_members ugm JOIN user_group_roles ugr ON ugr.group_id = ugm.group_id
                      WHERE ugm.user_id = u.id AND ugr.role_id = r.id))), ''),
            'last_login_at', COALESCE(EXTRACT(EPOCH FROM u.last_login_at)::bigint, 0)::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM u.created_at)::bigint, 0)::text)`,
		textMatch: `u.search_tsv @@ pq.value OR starts_with(lower(u.id), lower(@query::text))
		  OR starts_with(lower(u.email), lower(@query::text))
		  OR starts_with(lower(u.linux_username), lower(@query::text)) OR EXISTS (SELECT 1 FROM roles r
            WHERE r.is_deleted = FALSE AND to_tsvector('simple'::regconfig, r.name) @@ pq.value
              AND (EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = r.id)
                OR EXISTS (SELECT 1 FROM user_group_members ugm JOIN user_group_roles ugr ON ugr.group_id = ugm.group_id
                    WHERE ugm.user_id = u.id AND ugr.role_id = r.id)))`,
		scopeMatch: `EXISTS (SELECT 1 FROM user_group_members m JOIN user_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
            WHERE m.user_id = u.id AND m.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"disabled": {predicate: "u.disabled = ANY({{arg}}::boolean[])", kind: "bool"},
			"role": {predicate: `EXISTS (SELECT 1 FROM roles r WHERE r.is_deleted = FALSE AND r.name = ANY({{arg}}::text[])
                    AND (EXISTS (SELECT 1 FROM user_roles ur WHERE ur.user_id = u.id AND ur.role_id = r.id)
                      OR EXISTS (SELECT 1 FROM user_group_members ugm JOIN user_group_roles ugr ON ugr.group_id = ugm.group_id
                          WHERE ugm.user_id = u.id AND ugr.role_id = r.id)))`, kind: "text"},
		},
		dateFilters: map[string]string{"last_login_at": "u.last_login_at", "created_at": "u.created_at"},
		sorts:       map[string]string{"email": "u.email", "display_name": "u.display_name", "disabled": "u.disabled", "last_login_at": "u.last_login_at", "created_at": "u.created_at"},
		defaultSort: "created_at",
	},
	"device_groups": groupSearchFacet("device_groups g", "device_group_members", "device_id", "devices"),
	"user_groups":   groupSearchFacet("user_groups g", "user_group_members", "user_id", "users"),
	"executions": {
		from: "executions e JOIN devices d ON d.id = e.device_id AND d.is_deleted = FALSE LEFT JOIN actions a ON a.id = e.action_id AND a.is_deleted = FALSE",
		where: `@assigned_user_id::text IS NULL
          OR EXISTS (SELECT 1 FROM device_assigned_users dau WHERE dau.device_id = e.device_id AND dau.user_id = @assigned_user_id)
          OR EXISTS (SELECT 1 FROM device_assigned_groups dag JOIN user_group_members ugm ON ugm.group_id = dag.group_id
              JOIN user_groups ug ON ug.id = dag.group_id AND ug.is_deleted = FALSE
              WHERE dag.device_id = e.device_id AND ugm.user_id = @assigned_user_id)`,
		id: "e.id", name: "COALESCE(a.name, e.id)", description: "d.hostname", memberCount: "0::bigint",
		fields: `jsonb_build_object(
            'action_name', COALESCE(a.name, ''), 'device_hostname', d.hostname,
			'status', e.status, 'action_type', e.action_type::text, 'device_id', e.device_id,
			'action_id', COALESCE(e.action_id, ''), 'desired_state', e.desired_state::text,
			'changed', e.changed::text, 'duration_ms', COALESCE(e.duration_ms, 0)::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM e.created_at)::bigint, 0)::text)`,
		textMatch: `e.search_tsv @@ pq.value OR a.search_tsv @@ pq.value OR d.search_tsv @@ pq.value
		  OR starts_with(lower(e.id), lower(@query::text))
		  OR starts_with(lower(e.device_id), lower(@query::text))`,
		scopeMatch: `EXISTS (SELECT 1 FROM device_group_members m JOIN device_groups g ON g.id = m.group_id AND g.is_deleted = FALSE
            WHERE m.device_id = e.device_id AND m.group_id = ANY(@scope_group_ids::text[]))`,
		tagFilters: map[string]searchFilter{
			"status":      {predicate: "e.status = ANY({{arg}}::text[])", kind: "text"},
			"action_type": {predicate: "e.action_type = ANY({{arg}}::integer[])", kind: "int"},
			"device_id":   {predicate: "e.device_id = ANY({{arg}}::text[])", kind: "text"},
		},
		dateFilters: map[string]string{"created_at": "e.created_at"},
		sorts:       map[string]string{"device_hostname": "d.hostname", "status": "e.status", "action_type": "e.action_type", "created_at": "e.created_at"},
		defaultSort: "created_at",
	},
	"audit_events": auditSearchFacet(),
}

func groupSearchFacet(from, membership, memberColumn, liveTable string) searchFacet {
	count := fmt.Sprintf(`(SELECT COUNT(*) FROM %s m JOIN %s live
            ON live.id = m.%s AND live.is_deleted = FALSE WHERE m.group_id = g.id)`, membership, liveTable, memberColumn)
	return searchFacet{
		from: from, where: "g.is_deleted = FALSE", id: "g.id", name: "g.name", description: "g.description",
		memberCount: count,
		fields: fmt.Sprintf(`jsonb_build_object(
            'name', g.name, 'description', g.description, 'is_dynamic', g.is_dynamic::text,
			'member_count', %s::text,
            'created_at', COALESCE(EXTRACT(EPOCH FROM g.created_at)::bigint, 0)::text)`, count),
		textMatch: "g.search_tsv @@ pq.value OR starts_with(lower(g.id), lower(@query::text))", scopeMatch: "g.id = ANY(@scope_group_ids::text[])",
		tagFilters: map[string]searchFilter{
			"is_dynamic":   {predicate: "g.is_dynamic = ANY({{arg}}::boolean[])", kind: "bool"},
			"member_count": {predicate: count + " = ANY({{arg}}::bigint[])", kind: "int64"},
		},
		dateFilters: map[string]string{"created_at": "g.created_at"},
		sorts:       map[string]string{"name": "g.name", "member_count": count, "created_at": "g.created_at"},
		defaultSort: "created_at",
	}
}

func auditSearchFacet() searchFacet {
	return searchFacet{
		from: `(
		  SELECT e.effect_id AS id, e.resource_type AS stream_type, e.action AS event_type,
		         e.resource_id AS stream_id, e.occurred_at, o.actor_type, o.actor_id, o.request_descriptor,
				 o.search_tsv || to_tsvector('simple'::regconfig,
				     regexp_replace(o.request_descriptor, '[^[:alnum:]]+', ' ', 'g')) AS operation_tsv,
                 to_tsvector('simple'::regconfig, e.resource_type || ' ' || e.action || ' ' || e.resource_id) AS effect_tsv
          FROM audit_effects e JOIN audit_operations o ON o.operation_id = e.operation_id
          WHERE e.stream = 'control'
          UNION ALL
		  SELECT o.operation_id,
		         CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION' THEN 'authentication' ELSE 'operation' END,
		         CASE WHEN o.operation_class = 'REJECTED_AUTHENTICATION' THEN 'AUTHENTICATION_REJECTED' ELSE o.operation_class END,
		         o.operation_id, o.occurred_at, o.actor_type, o.actor_id, o.request_descriptor,
				 o.search_tsv || to_tsvector('simple'::regconfig,
				     regexp_replace(o.request_descriptor, '[^[:alnum:]]+', ' ', 'g')), ''::tsvector
          FROM audit_operations o
          WHERE o.stream = 'control' AND NOT EXISTS (SELECT 1 FROM audit_effects e WHERE e.operation_id = o.operation_id)
        ) ev`,
		where: "TRUE", id: "ev.id", name: "ev.event_type", description: "ev.request_descriptor", memberCount: "0::bigint",
		fields: `jsonb_build_object(
            'event_type', ev.event_type, 'stream_type', ev.stream_type,
			'actor_type', ev.actor_type, 'actor_id', ev.actor_id, 'stream_id', ev.stream_id,
            'occurred_at', EXTRACT(EPOCH FROM ev.occurred_at)::bigint::text)`,
		textMatch: `ev.operation_tsv @@ pq.value OR ev.effect_tsv @@ pq.value
		  OR starts_with(lower(ev.id), lower(@query::text))`, scopeMatch: "TRUE",
		tagFilters: map[string]searchFilter{
			"stream_type": {predicate: "ev.stream_type = ANY({{arg}}::text[])", kind: "text"},
			"actor_type":  {predicate: "ev.actor_type = ANY({{arg}}::text[])", kind: "text"},
			"actor_id":    {predicate: "ev.actor_id = ANY({{arg}}::text[])", kind: "text"},
		},
		dateFilters: map[string]string{"occurred_at": "ev.occurred_at"},
		sorts:       map[string]string{"event_type": "ev.event_type", "stream_type": "ev.stream_type", "actor_type": "ev.actor_type", "occurred_at": "ev.occurred_at"},
		defaultSort: "occurred_at",
	}
}

// Search uses PostgreSQL FTS and current relational joins; no derived service
// or asynchronous index can sit between a committed row and its visibility.
func (s *Store) Search(ctx context.Context, p SearchParams) ([]SearchRow, int64, error) {
	if ctx == nil || utf8.RuneCountInString(p.Query) > 1024 || p.Offset < 0 || p.Offset > 100_000 || p.Limit < 1 || p.Limit > 200 {
		return nil, 0, ErrInvalidSearch
	}
	facet, ok := searchFacets[p.Scope]
	if !ok {
		return nil, 0, ErrInvalidSearch
	}
	if p.OnlineSince.IsZero() {
		p.OnlineSince = time.Now().UTC().Add(-5 * time.Minute)
	}
	sortField := p.SortField
	if sortField == "" {
		sortField = facet.defaultSort
	}
	sortExpression, ok := facet.sorts[sortField]
	if !ok {
		return nil, 0, ErrInvalidSearch
	}

	args := pgx.NamedArgs{
		"query": p.Query, "offset": p.Offset, "limit": p.Limit,
		"scope_group_ids": p.ScopeGroupIDs, "assigned_user_id": p.AssignedUserID,
		"online_since": p.OnlineSince.UTC(),
	}
	conditions := []string{facet.where, "(@query::text = '' OR (pq.value IS NOT NULL AND (" + facet.textMatch + ")))"}
	if p.ScopeRestricted {
		conditions = append(conditions, "("+facet.scopeMatch+")")
	}

	dates := append([]SearchDateRange(nil), p.DateRanges...)
	sort.Slice(dates, func(i, j int) bool { return dates[i].Field < dates[j].Field })
	for i, dateRange := range dates {
		expression, ok := facet.dateFilters[dateRange.Field]
		if !ok || dateRange.Start < 0 || dateRange.End < 0 || (dateRange.Start > 0 && dateRange.End > 0 && dateRange.Start > dateRange.End) {
			return nil, 0, ErrInvalidSearch
		}
		if dateRange.Start > 0 {
			name := "date_start_" + strconv.Itoa(i)
			args[name] = dateRange.Start
			conditions = append(conditions, expression+" >= to_timestamp(@"+name+")")
		}
		if dateRange.End > 0 {
			name := "date_end_" + strconv.Itoa(i)
			args[name] = dateRange.End
			conditions = append(conditions, expression+" <= to_timestamp(@"+name+")")
		}
	}

	filterNames := make([]string, 0, len(p.TagFilters))
	for name := range p.TagFilters {
		filterNames = append(filterNames, name)
	}
	sort.Strings(filterNames)
	for i, name := range filterNames {
		filter, ok := facet.tagFilters[name]
		values := compactFilterValues(p.TagFilters[name])
		if !ok || len(values) == 0 {
			return nil, 0, ErrInvalidSearch
		}
		argName := "tag_" + strconv.Itoa(i)
		predicate := filter.predicate
		switch filter.kind {
		case "text":
			args[argName] = values
		case "int":
			parsed := make([]int32, len(values))
			for i, value := range values {
				n, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return nil, 0, ErrInvalidSearch
				}
				parsed[i] = int32(n)
			}
			args[argName] = parsed
		case "int64":
			parsed := make([]int64, len(values))
			for i, value := range values {
				n, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return nil, 0, ErrInvalidSearch
				}
				parsed[i] = n
			}
			args[argName] = parsed
		case "bool":
			parsed := make([]bool, len(values))
			for i, value := range values {
				b, err := strconv.ParseBool(value)
				if err != nil {
					return nil, 0, ErrInvalidSearch
				}
				parsed[i] = b
			}
			args[argName] = parsed
		case "device_status":
			if len(values) == 2 && contains(values, "online") && contains(values, "offline") {
				continue
			}
			if len(values) != 1 || (values[0] != "online" && values[0] != "offline") {
				return nil, 0, ErrInvalidSearch
			}
			if values[0] == "online" {
				predicate = "d.last_seen_at > @online_since"
			} else {
				predicate = "(d.last_seen_at IS NULL OR d.last_seen_at <= @online_since)"
			}
		default:
			return nil, 0, ErrInvalidSearch
		}
		predicate = strings.ReplaceAll(predicate, "{{arg}}", "@"+argName)
		conditions = append(conditions, "("+predicate+")")
	}

	direction := "ASC"
	if p.Descending {
		direction = "DESC"
	}
	query := fmt.Sprintf(`WITH %s,
prefix_query AS (
    SELECT CASE WHEN btrim(@query::text) = '' THEN NULL::tsquery ELSE (
        SELECT to_tsquery('simple'::regconfig,
            string_agg(quote_literal(term) || ':*', ' & ' ORDER BY term))
        FROM unnest(tsvector_to_array(to_tsvector('simple'::regconfig, @query::text))) AS term
    ) END AS value
), matches AS (
    SELECT %s AS id, %s AS name, %s AS description, %s AS member_count,
           %s AS fields, %s AS sort_value
    FROM %s CROSS JOIN prefix_query pq
    WHERE %s
), total AS (SELECT COUNT(*)::bigint AS total_count FROM matches), page AS (
    SELECT * FROM matches ORDER BY sort_value %s NULLS LAST, id ASC
    LIMIT @limit OFFSET @offset
)
SELECT page.id, page.name, page.description, page.member_count, page.fields, total.total_count
FROM total LEFT JOIN page ON TRUE
ORDER BY page.sort_value %s NULLS LAST, page.id ASC`,
		assignmentGroupsCTE, facet.id, facet.name, facet.description, facet.memberCount,
		facet.fields, sortExpression, facet.from, strings.Join(conditions, " AND "), direction, direction)

	rows, err := s.pool.Query(ctx, query, args)
	if err != nil {
		return nil, 0, fmt.Errorf("search %s: %w", p.Scope, err)
	}
	defer rows.Close()

	results := make([]SearchRow, 0, p.Limit)
	var total int64
	for rows.Next() {
		var id, name, description *string
		var memberCount *int64
		var fields []byte
		if err := rows.Scan(&id, &name, &description, &memberCount, &fields, &total); err != nil {
			return nil, 0, fmt.Errorf("search %s scan: %w", p.Scope, err)
		}
		if id == nil {
			continue
		}
		result := SearchRow{ID: *id, Fields: make(map[string]string)}
		if name != nil {
			result.Name = *name
		}
		if description != nil {
			result.Description = *description
		}
		if memberCount != nil {
			result.MemberCount = *memberCount
		}
		if err := json.Unmarshal(fields, &result.Fields); err != nil {
			return nil, 0, fmt.Errorf("search %s fields: %w", p.Scope, err)
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("search %s rows: %w", p.Scope, err)
	}
	return results, total, nil
}

// RebuildSearchIndexes recreates the fixed PostgreSQL GIN indexes inside the
// same transaction as its audit evidence. Generated vectors remain current;
// this RPC is only an explicit physical-index maintenance operation.
func (s *Store) RebuildSearchIndexes(ctx context.Context, op AuditOperation) error {
	indexes := []string{
		"actions_search_idx", "action_sets_search_idx", "definitions_search_idx",
		"compliance_policies_search_idx", "devices_search_idx", "device_groups_search_idx",
		"users_search_idx", "user_groups_search_idx", "executions_search_idx",
		"audit_operations_search_idx",
	}
	_, err := s.WithAudit(ctx, op, func(ctx context.Context, tx *Tx, rec *AuditRecorder) error {
		for _, index := range indexes {
			// Every identifier comes from the fixed schema list above.
			if err := tx.exec(ctx, "REINDEX INDEX public."+index); err != nil {
				return fmt.Errorf("reindex %s: %w", index, err)
			}
		}
		rec.Effect(AuditEffect{
			ResourceType: "server_settings", ResourceID: "00000000000000000000000003",
			Action: "REBUILD_SEARCH", Outcome: EffectApplied,
		})
		return nil
	})
	if err != nil {
		return fmt.Errorf("rebuild search indexes: %w", err)
	}
	return nil
}

func compactFilterValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
