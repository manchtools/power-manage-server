-- +goose Up

-- Replace CreateToken with CreateToken:self in the default User role.
-- Self-scoped creates one-time tokens with 7-day expiry owned by the creator.
-- Unrestricted CreateToken must be granted explicitly via a role.
UPDATE roles_projection
SET permissions = array_append(array_remove(permissions, 'CreateToken'), 'CreateToken:self'),
    updated_at = now()
WHERE name = 'User' AND is_system = TRUE AND 'CreateToken' = ANY(permissions);

-- +goose Down

UPDATE roles_projection
SET permissions = array_append(array_remove(permissions, 'CreateToken:self'), 'CreateToken'),
    updated_at = now()
WHERE name = 'User' AND is_system = TRUE AND 'CreateToken:self' = ANY(permissions);
