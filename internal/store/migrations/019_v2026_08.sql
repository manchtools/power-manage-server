-- +goose Up

-- Drop the gateway identity projection (spec 41).
--
-- The table recorded one row per enrolled gateway: its id, certificate
-- fingerprint, expiry and revocation state. Every one of those facts describes
-- a process that no longer exists. Agents connect to control directly, control
-- issues and revokes only agent certificates, and the RPCs that read this table
-- (ListGateways, RevokeGatewayCertificate) went with the tier.
--
-- Dropped rather than left in place. An orphaned projection is worse than
-- clutter: it keeps a rebuild target that replays a stream nothing writes, and
-- it presents an operator-facing inventory of a component that cannot be
-- deployed — the kind of table someone later reads as evidence that gateways
-- are still a supported topology.
DROP TABLE IF EXISTS gateways_projection;

-- +goose Down

-- Deliberately irreversible. Restoring the schema would produce an empty
-- inventory of a tier that has no code left to populate it, so it would recover
-- the shape of the data and none of its meaning.
SELECT 1;
