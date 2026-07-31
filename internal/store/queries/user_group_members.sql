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

-- name: CountIdentityLinksForUser :one
SELECT COUNT(*) FROM identity_links WHERE user_id = $1;
