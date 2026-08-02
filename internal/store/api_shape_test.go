package store_test

// The audit contract made mechanical.
//
// Every ordinary state mutation commits through a primitive that requires its
// audit operation. The sole high-rate telemetry exception is named explicitly
// below. This is a property of the package's exported surface, so a new writer
// fails this test the day it is added, before it has a caller.

import (
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/server/internal/store"
)

// mutationCapableExports is the complete set of exported Store methods
// allowed to change database state. Each one writes its own evidence
// in the same transaction as the change it makes:
//
//   - WithAudit         the mutation door; refuses without an operation
//   - RecordOperation   WithAudit with no state change (sensitive read,
//     rejected authentication)
//   - WithAuditEffects  a continuation of an operation already on the
//     chain; appends effects, rewrites nothing
//   - RecordPublishedAuditAnchor appends an anchor point for a chain
//     position the caller has published off-host
//   - PruneAuditPrefix  the retention path; deletes an archived prefix
//     and writes its checkpoint in one transaction
//   - RebuildSearchIndexes reindexes fixed SQLite FTS5 facets and records
//     its maintenance effect in the same transaction
//   - RecordHeartbeatTelemetry is the one deliberate unaudited telemetry
//     writer; it coalesces live connection timestamps in bounded batches
//   - CleanupExpiredAuthStates deletes expired one-time OIDC state and records
//     the maintenance effect in the same transaction
//
// Adding an entry here is a deliberate act that has to survive review.
var mutationCapableExports = map[string]string{
	"WithAudit":                  "the audited mutation door",
	"RecordOperation":            "audited operation with no state change",
	"WithAuditEffects":           "audited continuation of an existing operation",
	"RecordPublishedAuditAnchor": "appends an anchor for a published chain position",
	"PruneAuditPrefix":           "archived-prefix deletion with its checkpoint",
	"RebuildSearchIndexes":       "audited SQLite FTS5 index maintenance",
	"RecordHeartbeatTelemetry":   "bounded high-rate telemetry exception",
	"CleanupExpiredAuthStates":   "audited one-time OIDC state cleanup",
}

// nonMutatingExports is every other exported method, each with the
// reason it cannot change state. Listing them explicitly is what makes
// the check exhaustive: an unlisted method fails, so a new export must
// be classified rather than silently admitted.
var nonMutatingExports = map[string]string{
	"Close":                            "releases the pool",
	"Ping":                             "read-only connectivity check",
	"SetLogger":                        "in-process wiring",
	"VerifyAuditChain":                 "recomputes and compares; writes nothing",
	"LatestAuditAnchor":                "read",
	"ListAuditAnchors":                 "read",
	"ListAuditCheckpoints":             "read",
	"GetAuditOperation":                "read",
	"ListAuditEffects":                 "read",
	"ListAuditEventRows":               "read",
	"CountAuditEventRows":              "read",
	"AuditChainTipOf":                  "read",
	"CountAuditOperations":             "read",
	"GetDevice":                        "read",
	"GetCurrentLuksKeyForAgent":        "read",
	"ListDeviceMaintenanceWindows":     "read",
	"GetDelivery":                      "read",
	"ListDueDeliveries":                "read",
	"ListDeviceDeliveries":             "read",
	"GetJob":                           "read",
	"GetLiveJobByDedupe":               "read",
	"ListClaimableJobs":                "read",
	"FindAuditRetentionBoundary":       "read",
	"WriteAuditPrefix":                 "read-only archive export",
	"GetManifestAction":                "read",
	"GetManifestActionSet":             "read",
	"ListManifestActionSetActions":     "read",
	"GetManifestDefinition":            "read",
	"ListManifestDefinitionActionSets": "read",
	"ListManifestDefinitionActions":    "read",
	"ListAuthoringActions":             "read",
	"CountAuthoringActions":            "read",
	"ListAuthoringAssignmentTargets":   "read",
	"GetAssignment":                    "read",
	"FindAssignment":                   "read",
	"ListAssignments":                  "read",
	"CountAssignments":                 "read",
	"ListAssignmentsForUser":           "read",
	"ListAvailableSources":             "read",
	"ListResolvedSources":              "read",
	"GetDeviceGroupID":                 "read",
	"GetDeviceGroup":                   "read",
	"ListDeviceGroupMembers":           "read",
	"ListDevicesForDynamicEvaluation":  "read",
	"ListDeviceGroups":                 "read",
	"CountDeviceGroups":                "read",
	"ListDeviceGroupsForDevice":        "read",
	"ListContainingActionSetIDs":       "read",
	"ListContainingDefinitionIDs":      "read",
	"ListAuthoringActionSets":          "read",
	"CountAuthoringActionSets":         "read",
	"GetRegistrationToken":             "read",
	"ListRegistrationTokens":           "read",
	"CountRegistrationTokens":          "read",
	"CountDevices":                     "read",
	"CountActions":                     "read",
	"CountActionSets":                  "read",
	"ListActionSetMembers":             "read",
	"ListAuthoringDefinitions":         "read",
	"CountAuthoringDefinitions":        "read",
	"CountDefinitions":                 "read",
	"ListDefinitionMembers":            "read",
	"GetAuthoringCompliancePolicy":     "read",
	"ListAuthoringCompliancePolicies":  "read",
	"CountAuthoringCompliancePolicies": "read",
	"ListCompliancePolicyRules":        "read",
	"ListCompliancePolicyIDsForAction": "read",
	"GetDeviceView":                    "read",
	"ListDeviceViews":                  "read",
	"CountDeviceViews":                 "read",
	"ListDeviceGroupIDs":               "read",
	"IsDeviceAssignedToUser":           "read",
	"ListDeviceAssignees":              "read",
	"ListDeviceInventory":              "read",
	"GetOSQueryResult":                 "read",
	"GetDeviceLogResult":               "read",
	"ListDeviceComplianceResults":      "read",
	"ListDeviceComplianceEvaluations":  "read",
	"GetExecution":                     "read",
	"ListExecutions":                   "read",
	"CountExecutions":                  "read",
	"ListDeviceLpsPasswords":           "read",
	"ListDeviceLuksKeys":               "read",
	"GetLpsPasswordForReveal":          "read",
	"GetLuksKeyForReveal":              "read",
	"GetLuksRevocationTarget":          "read",
	"GetOpenTerminalSession":           "read",
	"IsDeviceDirectlyAssignedToUser":   "read",
	"GetUser":                          "read",
	"CountUsers":                       "read",
	"GetUserEncryptionKey":             "read",

	// Identity reads.
	"GetUserByEmail":                         "read",
	"GetUserSessionState":                    "read",
	"ListUsers":                              "read",
	"ListUserPermissions":                    "read",
	"ListUserScopedGrants":                   "read",
	"ListUserRoleGrants":                     "read",
	"ListUserGroupRoleGrants":                "read",
	"ListInheritedRolesForUser":              "read",
	"ListUserGroupIDsForUser":                "read",
	"GetUserGroupView":                       "read",
	"ListUserGroups":                         "read",
	"CountUserGroups":                        "read",
	"ListUserGroupsForUser":                  "read",
	"ListUserGroupMembers":                   "read",
	"ListUsersForDynamicUserGroupEvaluation": "read",
	"ListUserSSHKeys":                        "read",
	"GetRole":                                "read",
	"GetRoleByName":                          "read",
	"ListRoles":                              "read",
	"CountRoles":                             "read",
	"CountRoleHolders":                       "read",
	"GetIdentityProvider":                    "read",
	"GetIdentityProviderBySlug":              "read",
	"ListIdentityProviders":                  "read",
	"ListEnabledIdentityProviders":           "read",
	"CountIdentityProviders":                 "read",
	"GetIdentityLink":                        "read",
	"ListIdentityLinksForUser":               "read",
	"IsTokenRevoked":                         "read",
	"GetServerSettings":                      "read",
	"CountLiveBootstrapAdminTokens":          "read",
	"Search":                                 "read",

	// Directory-provisioning reads.
	"ListSCIMUsers":                    "read",
	"CountSCIMUsers":                   "read",
	"FindSCIMUserByEmail":              "read",
	"FindSCIMUserByExternalID":         "read",
	"GetIdentityLinkByProviderAndUser": "read",
	"CountIdentityLinksForUser":        "read",
	"GetUserGroup":                     "read",
	"ListUserGroupMemberIDs":           "read",
	"GetSCIMGroupMapping":              "read",
	"GetSCIMGroupMappingByUserGroup":   "read",
	"ListSCIMGroupMappings":            "read",
}

// forbiddenExports are the shapes that would hand a caller a generic
// way into the database. Named separately so the failure message says
// what went wrong rather than only that an unknown method appeared.
var forbiddenExports = map[string]string{
	"Queries":     "would hand out the generated mutation surface",
	"Pool":        "would hand out the connection pool",
	"TestingPool": "would hand out the connection pool",
	"DB":          "would hand out the connection pool",
	"Conn":        "would hand out a raw connection",
	"Exec":        "would allow arbitrary statements",
	"Query":       "would allow arbitrary statements",
	"QueryRow":    "would allow arbitrary statements",
	"WithTx":      "would be an unaudited transaction",
	"Begin":       "would be an unaudited transaction",
	"Repos":       "would hand out repositories built on the raw handle",
	"SetRepos":    "would hand out repositories built on the raw handle",
}

func exportedStoreMethods(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeOf(&store.Store{})
	names := make([]string, 0, typ.NumMethod())
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	// Matches-zero guard: an empty enumeration would make every
	// assertion below vacuously true.
	require.NotEmpty(t, names, "no exported Store methods were enumerated; the reflection is mis-scoped")
	return names
}

// Every exported method is classified, and only the audited primitives
// may change state. An unclassified method fails: the default for a
// new export is "not allowed", not "assumed harmless".
func TestStoreAPI_OnlyAuditedPrimitivesCanMutate(t *testing.T) {
	var unclassified []string
	for _, name := range exportedStoreMethods(t) {
		if _, ok := forbiddenExports[name]; ok {
			t.Errorf("Store.%s is an unaudited door into the database: %s", name, forbiddenExports[name])
			continue
		}
		_, mutating := mutationCapableExports[name]
		_, readOnly := nonMutatingExports[name]
		switch {
		case mutating && readOnly:
			t.Errorf("Store.%s is classified both ways", name)
		case !mutating && !readOnly:
			unclassified = append(unclassified, name)
		}
	}
	assert.Empty(t, unclassified,
		"every exported Store method must be classified as audited-mutating or read-only; "+
			"if one of these writes state it needs to go through WithAudit, and if it does not it belongs in nonMutatingExports: %v",
		unclassified)
}

// The allowlist is not allowed to drift out of existence either: a
// method named in it that no longer exists is a stale entry that would
// silently widen the check.
func TestStoreAPI_ClassificationHasNoStaleEntries(t *testing.T) {
	present := map[string]bool{}
	for _, name := range exportedStoreMethods(t) {
		present[name] = true
	}

	var stale []string
	for name := range mutationCapableExports {
		if !present[name] {
			stale = append(stale, "mutationCapableExports: "+name)
		}
	}
	for name := range nonMutatingExports {
		if !present[name] {
			stale = append(stale, "nonMutatingExports: "+name)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale, "the API classification names methods that no longer exist: %v", stale)
}

// The store must expose no exported FIELD either — an exported pool or
// query handle would be the same escape hatch by another route.
func TestStoreAPI_HasNoExportedFields(t *testing.T) {
	typ := reflect.TypeOf(store.Store{})
	require.Positive(t, typ.NumField(), "matches-zero guard: Store has no fields to inspect")

	var exported []string
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			exported = append(exported, f.Name)
		}
	}
	assert.Empty(t, exported, "Store must expose no field; these bypass the audited door: %v", exported)
}
