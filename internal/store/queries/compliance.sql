-- Compliance queries

-- name: GetDeviceComplianceResults :many
SELECT * FROM compliance_results_projection
WHERE device_id = $1
ORDER BY action_name;

-- name: GetDeviceComplianceSummary :one
SELECT compliance_status, compliance_total, compliance_passing, compliance_checked_at
FROM devices_projection WHERE id = $1;
