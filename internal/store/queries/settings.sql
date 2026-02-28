-- name: GetServerSettings :one
SELECT * FROM server_settings_projection WHERE id = 'global';
