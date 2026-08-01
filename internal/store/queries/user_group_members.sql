-- User-group membership. Membership confers the group's role grants,
-- so every write here is an audited mutation.

-- name: InsertUserGroupMember :execrows
-- Idempotent: re-asserting a membership the subject already has is not
-- an error, and must not look like a fresh grant in the audit record.
INSERT INTO user_group_members (group_id, user_id, added_at, added_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: DeleteUserGroupMember :execrows
DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2;

-- name: ListUserGroupMemberIDs :many
SELECT user_id FROM user_group_members WHERE group_id = $1 ORDER BY user_id;

-- name: ListUserGroupMembers :many
SELECT m.user_id, u.email, m.added_at
FROM user_group_members m
JOIN users u ON u.id = m.user_id AND u.is_deleted = FALSE
WHERE m.group_id = $1
ORDER BY m.user_id;

-- name: AddStaticUserGroupMember :execrows
INSERT INTO user_group_members (group_id, user_id, added_at, added_by)
SELECT sqlc.arg(group_id), sqlc.arg(user_id), sqlc.arg(added_at), sqlc.arg(added_by)
FROM user_groups g
JOIN users u ON u.id = sqlc.arg(user_id) AND u.is_deleted = FALSE
WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE AND g.is_dynamic = FALSE
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveStaticUserGroupMember :execrows
DELETE FROM user_group_members m
USING user_groups g
WHERE m.group_id = sqlc.arg(group_id)
  AND m.user_id = sqlc.arg(user_id)
  AND g.id = m.group_id AND g.is_deleted = FALSE AND g.is_dynamic = FALSE;

-- name: AddDynamicUserGroupMembers :many
INSERT INTO user_group_members (group_id, user_id, added_at, added_by)
SELECT sqlc.arg(group_id), wanted.user_id, sqlc.arg(added_at), sqlc.arg(added_by)
FROM unnest(sqlc.arg(user_ids)::text[]) AS wanted(user_id)
JOIN users u ON u.id = wanted.user_id AND u.is_deleted = FALSE
WHERE EXISTS (
    SELECT 1 FROM user_groups g
    WHERE g.id = sqlc.arg(group_id) AND g.is_deleted = FALSE AND g.is_dynamic = TRUE
)
ON CONFLICT (group_id, user_id) DO NOTHING
RETURNING user_id;

-- name: RemoveDynamicUserGroupMembers :many
DELETE FROM user_group_members m
USING user_groups g
WHERE m.group_id = sqlc.arg(group_id)
  AND m.user_id = ANY(sqlc.arg(user_ids)::text[])
  AND g.id = m.group_id AND g.is_deleted = FALSE AND g.is_dynamic = TRUE
RETURNING m.user_id;

-- name: CountIdentityLinksForUser :one
SELECT COUNT(*) FROM identity_links WHERE user_id = $1;
