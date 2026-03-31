package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/crypto"
	"github.com/manchtools/power-manage/server/internal/search"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// ControlService implements the ControlService Connect-RPC service.
type ControlService struct {
	registration  *RegistrationHandler
	auth          *AuthHandler
	totp          *TOTPHandler
	user          *UserHandler
	device        *DeviceHandler
	token         *TokenHandler
	action        *ActionHandler
	actionSet     *ActionSetHandler
	definition    *DefinitionHandler
	deviceGroup   *DeviceGroupHandler
	assignment    *AssignmentHandler
	userSelection *UserSelectionHandler
	audit         *AuditHandler
	osquery       *OSQueryHandler
	logs          *LogsHandler
	role          *RoleHandler
	userGroup     *UserGroupHandler
	idp           *IDPHandler
	sso           *SSOHandler
	identityLink  *IdentityLinkHandler
	compliance       *ComplianceHandler
	compliancePolicy *CompliancePolicyHandler
	certificate      *CertificateHandler
	search           *SearchHandler
	settings         *SettingsHandler
	systemActions    *SystemActionManager
}

// ControlServiceConfig holds configuration for the control service.
type ControlServiceConfig struct {
	PasswordAuthEnabled       bool
	SSOCallbackBaseURL        string
	SCIMBaseURL               string
}

// NewControlService creates a new control service.
func NewControlService(st *store.Store, jwtManager *auth.JWTManager, signer ActionSigner, certAuth *ca.CA, gatewayURL string, logger *slog.Logger, enc *crypto.Encryptor, cfg ControlServiceConfig) *ControlService {
	actionHandler := NewActionHandler(st, logger.With("component", "action_handler"), signer)
	systemActions := NewSystemActionManager(st, signer, logger)
	settingsHandler := NewSettingsHandler(st, logger, systemActions)
	return &ControlService{
		registration:  NewRegistrationHandler(st, certAuth, gatewayURL, logger),
		auth:          NewAuthHandler(st, logger.With("component", "auth_handler"), jwtManager),
		totp:          NewTOTPHandler(st, logger.With("component", "totp_handler"), jwtManager, enc, ""),
		user:          NewUserHandler(st, logger.With("component", "user_handler"), systemActions),
		device:        NewDeviceHandler(st, enc, logger.With("component", "device_handler")),
		token:         NewTokenHandler(st, logger.With("component", "token_handler")),
		action:        actionHandler,
		actionSet:     NewActionSetHandler(st, logger.With("component", "action_set_handler")),
		definition:    NewDefinitionHandler(st, logger.With("component", "definition_handler")),
		deviceGroup:   NewDeviceGroupHandler(st, logger.With("component", "device_group_handler")),
		assignment:    NewAssignmentHandler(st, logger.With("component", "assignment_handler"), actionHandler),
		userSelection: NewUserSelectionHandler(st, logger.With("component", "user_selection_handler")),
		audit:         NewAuditHandler(st, logger.With("component", "audit_handler")),
		osquery:       NewOSQueryHandler(st, logger.With("component", "osquery_handler")),
		logs:          NewLogsHandler(st, logger.With("component", "logs_handler")),
		role:          NewRoleHandler(st, logger.With("component", "role_handler")),
		userGroup:     NewUserGroupHandler(st, logger.With("component", "user_group_handler")),
		idp:           NewIDPHandler(st, enc, cfg.SCIMBaseURL, logger.With("component", "idp_handler")),
		sso:           NewSSOHandler(st, logger.With("component", "sso_handler"), jwtManager, enc, cfg.PasswordAuthEnabled, cfg.SSOCallbackBaseURL),
		identityLink:  NewIdentityLinkHandler(st, logger.With("component", "identity_link_handler")),
		compliance:       NewComplianceHandler(st, logger.With("component", "compliance_handler")),
		compliancePolicy: NewCompliancePolicyHandler(st, logger.With("component", "compliance_policy_handler")),
		certificate:      NewCertificateHandler(st, certAuth, logger),
		search:           NewSearchHandler(logger.With("component", "search_handler")),
		settings:         settingsHandler,
		systemActions:    systemActions,
	}
}

// SystemActions returns the system action manager for startup sync.
func (s *ControlService) SystemActions() *SystemActionManager {
	return s.systemActions
}

// SetTaskQueueClient propagates the Asynq client to all sub-handlers that
// dispatch messages to agents. This enables dual-write during migration.
func (s *ControlService) SetTaskQueueClient(c *taskqueue.Client) {
	s.action.SetTaskQueueClient(c)
	s.osquery.SetTaskQueueClient(c)
	s.logs.SetTaskQueueClient(c)
	s.device.SetTaskQueueClient(c)
}

// SetSearchIndex propagates the search index to all sub-handlers that
// enqueue search index updates after mutations.
func (s *ControlService) SetSearchIndex(idx *search.Index) {
	s.search.SetSearchIndex(idx)
	s.action.SetSearchIndex(idx)
	s.actionSet.SetSearchIndex(idx)
	s.definition.SetSearchIndex(idx)
	s.compliancePolicy.SetSearchIndex(idx)
	s.device.SetSearchIndex(idx)
	s.user.SetSearchIndex(idx)
}

var _ pmv1connect.ControlServiceHandler = (*ControlService)(nil)

// Agent Registration
func (s *ControlService) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	return s.registration.Register(ctx, req)
}

// Certificate Renewal
func (s *ControlService) RenewCertificate(ctx context.Context, req *connect.Request[pm.RenewCertificateRequest]) (*connect.Response[pm.RenewCertificateResponse], error) {
	return s.certificate.RenewCertificate(ctx, req)
}

// Authentication
func (s *ControlService) Login(ctx context.Context, req *connect.Request[pm.LoginRequest]) (*connect.Response[pm.LoginResponse], error) {
	return s.auth.Login(ctx, req)
}

func (s *ControlService) RefreshToken(ctx context.Context, req *connect.Request[pm.RefreshTokenRequest]) (*connect.Response[pm.RefreshTokenResponse], error) {
	return s.auth.RefreshToken(ctx, req)
}

func (s *ControlService) Logout(ctx context.Context, req *connect.Request[pm.LogoutRequest]) (*connect.Response[pm.LogoutResponse], error) {
	return s.auth.Logout(ctx, req)
}

func (s *ControlService) GetCurrentUser(ctx context.Context, req *connect.Request[pm.GetCurrentUserRequest]) (*connect.Response[pm.GetCurrentUserResponse], error) {
	return s.auth.GetCurrentUser(ctx, req)
}

func (s *ControlService) VerifyLoginTOTP(ctx context.Context, req *connect.Request[pm.VerifyLoginTOTPRequest]) (*connect.Response[pm.VerifyLoginTOTPResponse], error) {
	return s.totp.VerifyLoginTOTP(ctx, req)
}

// TOTP Two-Factor Authentication
func (s *ControlService) SetupTOTP(ctx context.Context, req *connect.Request[pm.SetupTOTPRequest]) (*connect.Response[pm.SetupTOTPResponse], error) {
	return s.totp.SetupTOTP(ctx, req)
}

func (s *ControlService) VerifyTOTP(ctx context.Context, req *connect.Request[pm.VerifyTOTPRequest]) (*connect.Response[pm.VerifyTOTPResponse], error) {
	return s.totp.VerifyTOTP(ctx, req)
}

func (s *ControlService) DisableTOTP(ctx context.Context, req *connect.Request[pm.DisableTOTPRequest]) (*connect.Response[pm.DisableTOTPResponse], error) {
	return s.totp.DisableTOTP(ctx, req)
}

func (s *ControlService) AdminDisableUserTOTP(ctx context.Context, req *connect.Request[pm.AdminDisableUserTOTPRequest]) (*connect.Response[pm.AdminDisableUserTOTPResponse], error) {
	return s.totp.AdminDisableUserTOTP(ctx, req)
}

func (s *ControlService) GetTOTPStatus(ctx context.Context, req *connect.Request[pm.GetTOTPStatusRequest]) (*connect.Response[pm.GetTOTPStatusResponse], error) {
	return s.totp.GetTOTPStatus(ctx, req)
}

func (s *ControlService) RegenerateBackupCodes(ctx context.Context, req *connect.Request[pm.RegenerateBackupCodesRequest]) (*connect.Response[pm.RegenerateBackupCodesResponse], error) {
	return s.totp.RegenerateBackupCodes(ctx, req)
}

// Users
func (s *ControlService) CreateUser(ctx context.Context, req *connect.Request[pm.CreateUserRequest]) (*connect.Response[pm.CreateUserResponse], error) {
	return s.user.CreateUser(ctx, req)
}

func (s *ControlService) GetUser(ctx context.Context, req *connect.Request[pm.GetUserRequest]) (*connect.Response[pm.GetUserResponse], error) {
	return s.user.GetUser(ctx, req)
}

func (s *ControlService) ListUsers(ctx context.Context, req *connect.Request[pm.ListUsersRequest]) (*connect.Response[pm.ListUsersResponse], error) {
	return s.user.ListUsers(ctx, req)
}

func (s *ControlService) UpdateUserEmail(ctx context.Context, req *connect.Request[pm.UpdateUserEmailRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserEmail(ctx, req)
}

func (s *ControlService) UpdateUserPassword(ctx context.Context, req *connect.Request[pm.UpdateUserPasswordRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserPassword(ctx, req)
}

func (s *ControlService) SetUserDisabled(ctx context.Context, req *connect.Request[pm.SetUserDisabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.SetUserDisabled(ctx, req)
}

func (s *ControlService) UpdateUserProfile(ctx context.Context, req *connect.Request[pm.UpdateUserProfileRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserProfile(ctx, req)
}

func (s *ControlService) DeleteUser(ctx context.Context, req *connect.Request[pm.DeleteUserRequest]) (*connect.Response[pm.DeleteUserResponse], error) {
	return s.user.DeleteUser(ctx, req)
}

func (s *ControlService) UpdateUserLinuxUsername(ctx context.Context, req *connect.Request[pm.UpdateUserLinuxUsernameRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserLinuxUsername(ctx, req)
}

func (s *ControlService) AddUserSshKey(ctx context.Context, req *connect.Request[pm.AddUserSshKeyRequest]) (*connect.Response[pm.AddUserSshKeyResponse], error) {
	return s.user.AddUserSshKey(ctx, req)
}

func (s *ControlService) RemoveUserSshKey(ctx context.Context, req *connect.Request[pm.RemoveUserSshKeyRequest]) (*connect.Response[pm.RemoveUserSshKeyResponse], error) {
	return s.user.RemoveUserSshKey(ctx, req)
}

func (s *ControlService) UpdateUserSshSettings(ctx context.Context, req *connect.Request[pm.UpdateUserSshSettingsRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserSshSettings(ctx, req)
}

// Devices
func (s *ControlService) ListDevices(ctx context.Context, req *connect.Request[pm.ListDevicesRequest]) (*connect.Response[pm.ListDevicesResponse], error) {
	return s.device.ListDevices(ctx, req)
}

func (s *ControlService) GetDevice(ctx context.Context, req *connect.Request[pm.GetDeviceRequest]) (*connect.Response[pm.GetDeviceResponse], error) {
	return s.device.GetDevice(ctx, req)
}

func (s *ControlService) SetDeviceLabel(ctx context.Context, req *connect.Request[pm.SetDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	return s.device.SetDeviceLabel(ctx, req)
}

func (s *ControlService) RemoveDeviceLabel(ctx context.Context, req *connect.Request[pm.RemoveDeviceLabelRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	return s.device.RemoveDeviceLabel(ctx, req)
}

func (s *ControlService) DeleteDevice(ctx context.Context, req *connect.Request[pm.DeleteDeviceRequest]) (*connect.Response[pm.DeleteDeviceResponse], error) {
	return s.device.DeleteDevice(ctx, req)
}

func (s *ControlService) AssignDevice(ctx context.Context, req *connect.Request[pm.AssignDeviceRequest]) (*connect.Response[pm.AssignDeviceResponse], error) {
	return s.device.AssignDevice(ctx, req)
}

func (s *ControlService) UnassignDevice(ctx context.Context, req *connect.Request[pm.UnassignDeviceRequest]) (*connect.Response[pm.UnassignDeviceResponse], error) {
	return s.device.UnassignDevice(ctx, req)
}

func (s *ControlService) SetDeviceSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceResponse], error) {
	return s.device.SetDeviceSyncInterval(ctx, req)
}

func (s *ControlService) ListDeviceAssignees(ctx context.Context, req *connect.Request[pm.ListDeviceAssigneesRequest]) (*connect.Response[pm.ListDeviceAssigneesResponse], error) {
	return s.device.ListDeviceAssignees(ctx, req)
}

// Registration Tokens
func (s *ControlService) CreateToken(ctx context.Context, req *connect.Request[pm.CreateTokenRequest]) (*connect.Response[pm.CreateTokenResponse], error) {
	return s.token.CreateToken(ctx, req)
}

func (s *ControlService) GetToken(ctx context.Context, req *connect.Request[pm.GetTokenRequest]) (*connect.Response[pm.GetTokenResponse], error) {
	return s.token.GetToken(ctx, req)
}

func (s *ControlService) ListTokens(ctx context.Context, req *connect.Request[pm.ListTokensRequest]) (*connect.Response[pm.ListTokensResponse], error) {
	return s.token.ListTokens(ctx, req)
}

func (s *ControlService) RenameToken(ctx context.Context, req *connect.Request[pm.RenameTokenRequest]) (*connect.Response[pm.UpdateTokenResponse], error) {
	return s.token.RenameToken(ctx, req)
}

func (s *ControlService) SetTokenDisabled(ctx context.Context, req *connect.Request[pm.SetTokenDisabledRequest]) (*connect.Response[pm.UpdateTokenResponse], error) {
	return s.token.SetTokenDisabled(ctx, req)
}

func (s *ControlService) DeleteToken(ctx context.Context, req *connect.Request[pm.DeleteTokenRequest]) (*connect.Response[pm.DeleteTokenResponse], error) {
	return s.token.DeleteToken(ctx, req)
}

// Actions (single executable)
func (s *ControlService) CreateAction(ctx context.Context, req *connect.Request[pm.CreateActionRequest]) (*connect.Response[pm.CreateActionResponse], error) {
	return s.action.CreateAction(ctx, req)
}

func (s *ControlService) GetAction(ctx context.Context, req *connect.Request[pm.GetActionRequest]) (*connect.Response[pm.GetActionResponse], error) {
	return s.action.GetAction(ctx, req)
}

func (s *ControlService) ListActions(ctx context.Context, req *connect.Request[pm.ListActionsRequest]) (*connect.Response[pm.ListActionsResponse], error) {
	return s.action.ListActions(ctx, req)
}

func (s *ControlService) RenameAction(ctx context.Context, req *connect.Request[pm.RenameActionRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	return s.action.RenameAction(ctx, req)
}

func (s *ControlService) UpdateActionDescription(ctx context.Context, req *connect.Request[pm.UpdateActionDescriptionRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	return s.action.UpdateActionDescription(ctx, req)
}

func (s *ControlService) UpdateActionParams(ctx context.Context, req *connect.Request[pm.UpdateActionParamsRequest]) (*connect.Response[pm.UpdateActionResponse], error) {
	return s.action.UpdateActionParams(ctx, req)
}

func (s *ControlService) DeleteAction(ctx context.Context, req *connect.Request[pm.DeleteActionRequest]) (*connect.Response[pm.DeleteActionResponse], error) {
	return s.action.DeleteAction(ctx, req)
}

// Action Sets (collection of actions)
func (s *ControlService) CreateActionSet(ctx context.Context, req *connect.Request[pm.CreateActionSetRequest]) (*connect.Response[pm.CreateActionSetResponse], error) {
	return s.actionSet.CreateActionSet(ctx, req)
}

func (s *ControlService) GetActionSet(ctx context.Context, req *connect.Request[pm.GetActionSetRequest]) (*connect.Response[pm.GetActionSetResponse], error) {
	return s.actionSet.GetActionSet(ctx, req)
}

func (s *ControlService) ListActionSets(ctx context.Context, req *connect.Request[pm.ListActionSetsRequest]) (*connect.Response[pm.ListActionSetsResponse], error) {
	return s.actionSet.ListActionSets(ctx, req)
}

func (s *ControlService) RenameActionSet(ctx context.Context, req *connect.Request[pm.RenameActionSetRequest]) (*connect.Response[pm.UpdateActionSetResponse], error) {
	return s.actionSet.RenameActionSet(ctx, req)
}

func (s *ControlService) UpdateActionSetDescription(ctx context.Context, req *connect.Request[pm.UpdateActionSetDescriptionRequest]) (*connect.Response[pm.UpdateActionSetResponse], error) {
	return s.actionSet.UpdateActionSetDescription(ctx, req)
}

func (s *ControlService) DeleteActionSet(ctx context.Context, req *connect.Request[pm.DeleteActionSetRequest]) (*connect.Response[pm.DeleteActionSetResponse], error) {
	return s.actionSet.DeleteActionSet(ctx, req)
}

func (s *ControlService) AddActionToSet(ctx context.Context, req *connect.Request[pm.AddActionToSetRequest]) (*connect.Response[pm.AddActionToSetResponse], error) {
	return s.actionSet.AddActionToSet(ctx, req)
}

func (s *ControlService) RemoveActionFromSet(ctx context.Context, req *connect.Request[pm.RemoveActionFromSetRequest]) (*connect.Response[pm.RemoveActionFromSetResponse], error) {
	return s.actionSet.RemoveActionFromSet(ctx, req)
}

func (s *ControlService) ReorderActionInSet(ctx context.Context, req *connect.Request[pm.ReorderActionInSetRequest]) (*connect.Response[pm.ReorderActionInSetResponse], error) {
	return s.actionSet.ReorderActionInSet(ctx, req)
}

// Definitions (collection of action sets)
func (s *ControlService) CreateDefinition(ctx context.Context, req *connect.Request[pm.CreateDefinitionRequest]) (*connect.Response[pm.CreateDefinitionResponse], error) {
	return s.definition.CreateDefinition(ctx, req)
}

func (s *ControlService) GetDefinition(ctx context.Context, req *connect.Request[pm.GetDefinitionRequest]) (*connect.Response[pm.GetDefinitionResponse], error) {
	return s.definition.GetDefinition(ctx, req)
}

func (s *ControlService) ListDefinitions(ctx context.Context, req *connect.Request[pm.ListDefinitionsRequest]) (*connect.Response[pm.ListDefinitionsResponse], error) {
	return s.definition.ListDefinitions(ctx, req)
}

func (s *ControlService) RenameDefinition(ctx context.Context, req *connect.Request[pm.RenameDefinitionRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	return s.definition.RenameDefinition(ctx, req)
}

func (s *ControlService) UpdateDefinitionDescription(ctx context.Context, req *connect.Request[pm.UpdateDefinitionDescriptionRequest]) (*connect.Response[pm.UpdateDefinitionResponse], error) {
	return s.definition.UpdateDefinitionDescription(ctx, req)
}

func (s *ControlService) DeleteDefinition(ctx context.Context, req *connect.Request[pm.DeleteDefinitionRequest]) (*connect.Response[pm.DeleteDefinitionResponse], error) {
	return s.definition.DeleteDefinition(ctx, req)
}

func (s *ControlService) AddActionSetToDefinition(ctx context.Context, req *connect.Request[pm.AddActionSetToDefinitionRequest]) (*connect.Response[pm.AddActionSetToDefinitionResponse], error) {
	return s.definition.AddActionSetToDefinition(ctx, req)
}

func (s *ControlService) RemoveActionSetFromDefinition(ctx context.Context, req *connect.Request[pm.RemoveActionSetFromDefinitionRequest]) (*connect.Response[pm.RemoveActionSetFromDefinitionResponse], error) {
	return s.definition.RemoveActionSetFromDefinition(ctx, req)
}

func (s *ControlService) ReorderActionSetInDefinition(ctx context.Context, req *connect.Request[pm.ReorderActionSetInDefinitionRequest]) (*connect.Response[pm.ReorderActionSetInDefinitionResponse], error) {
	return s.definition.ReorderActionSetInDefinition(ctx, req)
}

// Device Groups
func (s *ControlService) CreateDeviceGroup(ctx context.Context, req *connect.Request[pm.CreateDeviceGroupRequest]) (*connect.Response[pm.CreateDeviceGroupResponse], error) {
	return s.deviceGroup.CreateDeviceGroup(ctx, req)
}

func (s *ControlService) GetDeviceGroup(ctx context.Context, req *connect.Request[pm.GetDeviceGroupRequest]) (*connect.Response[pm.GetDeviceGroupResponse], error) {
	return s.deviceGroup.GetDeviceGroup(ctx, req)
}

func (s *ControlService) ListDeviceGroups(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsRequest]) (*connect.Response[pm.ListDeviceGroupsResponse], error) {
	return s.deviceGroup.ListDeviceGroups(ctx, req)
}

func (s *ControlService) ListDeviceGroupsForDevice(ctx context.Context, req *connect.Request[pm.ListDeviceGroupsForDeviceRequest]) (*connect.Response[pm.ListDeviceGroupsForDeviceResponse], error) {
	return s.deviceGroup.ListDeviceGroupsForDevice(ctx, req)
}

func (s *ControlService) RenameDeviceGroup(ctx context.Context, req *connect.Request[pm.RenameDeviceGroupRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	return s.deviceGroup.RenameDeviceGroup(ctx, req)
}

func (s *ControlService) UpdateDeviceGroupDescription(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupDescriptionRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	return s.deviceGroup.UpdateDeviceGroupDescription(ctx, req)
}

func (s *ControlService) DeleteDeviceGroup(ctx context.Context, req *connect.Request[pm.DeleteDeviceGroupRequest]) (*connect.Response[pm.DeleteDeviceGroupResponse], error) {
	return s.deviceGroup.DeleteDeviceGroup(ctx, req)
}

func (s *ControlService) AddDeviceToGroup(ctx context.Context, req *connect.Request[pm.AddDeviceToGroupRequest]) (*connect.Response[pm.AddDeviceToGroupResponse], error) {
	return s.deviceGroup.AddDeviceToGroup(ctx, req)
}

func (s *ControlService) RemoveDeviceFromGroup(ctx context.Context, req *connect.Request[pm.RemoveDeviceFromGroupRequest]) (*connect.Response[pm.RemoveDeviceFromGroupResponse], error) {
	return s.deviceGroup.RemoveDeviceFromGroup(ctx, req)
}

func (s *ControlService) UpdateDeviceGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateDeviceGroupQueryRequest]) (*connect.Response[pm.UpdateDeviceGroupQueryResponse], error) {
	return s.deviceGroup.UpdateDeviceGroupQuery(ctx, req)
}

func (s *ControlService) ValidateDynamicQuery(ctx context.Context, req *connect.Request[pm.ValidateDynamicQueryRequest]) (*connect.Response[pm.ValidateDynamicQueryResponse], error) {
	return s.deviceGroup.ValidateDynamicQuery(ctx, req)
}

func (s *ControlService) EvaluateDynamicGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicGroupRequest]) (*connect.Response[pm.EvaluateDynamicGroupResponse], error) {
	return s.deviceGroup.EvaluateDynamicGroup(ctx, req)
}

func (s *ControlService) SetDeviceGroupSyncInterval(ctx context.Context, req *connect.Request[pm.SetDeviceGroupSyncIntervalRequest]) (*connect.Response[pm.UpdateDeviceGroupResponse], error) {
	return s.deviceGroup.SetDeviceGroupSyncInterval(ctx, req)
}

// Assignments
func (s *ControlService) CreateAssignment(ctx context.Context, req *connect.Request[pm.CreateAssignmentRequest]) (*connect.Response[pm.CreateAssignmentResponse], error) {
	return s.assignment.CreateAssignment(ctx, req)
}

func (s *ControlService) DeleteAssignment(ctx context.Context, req *connect.Request[pm.DeleteAssignmentRequest]) (*connect.Response[pm.DeleteAssignmentResponse], error) {
	return s.assignment.DeleteAssignment(ctx, req)
}

func (s *ControlService) ListAssignments(ctx context.Context, req *connect.Request[pm.ListAssignmentsRequest]) (*connect.Response[pm.ListAssignmentsResponse], error) {
	return s.assignment.ListAssignments(ctx, req)
}

func (s *ControlService) GetDeviceAssignments(ctx context.Context, req *connect.Request[pm.GetDeviceAssignmentsRequest]) (*connect.Response[pm.GetDeviceAssignmentsResponse], error) {
	return s.assignment.GetDeviceAssignments(ctx, req)
}

func (s *ControlService) GetUserAssignments(ctx context.Context, req *connect.Request[pm.GetUserAssignmentsRequest]) (*connect.Response[pm.GetUserAssignmentsResponse], error) {
	return s.assignment.GetUserAssignments(ctx, req)
}

// Action Dispatch & Execution
func (s *ControlService) DispatchAction(ctx context.Context, req *connect.Request[pm.DispatchActionRequest]) (*connect.Response[pm.DispatchActionResponse], error) {
	return s.action.DispatchAction(ctx, req)
}

func (s *ControlService) DispatchToMultiple(ctx context.Context, req *connect.Request[pm.DispatchToMultipleRequest]) (*connect.Response[pm.DispatchToMultipleResponse], error) {
	return s.action.DispatchToMultiple(ctx, req)
}

func (s *ControlService) DispatchAssignedActions(ctx context.Context, req *connect.Request[pm.DispatchAssignedActionsRequest]) (*connect.Response[pm.DispatchAssignedActionsResponse], error) {
	return s.action.DispatchAssignedActions(ctx, req)
}

func (s *ControlService) DispatchActionSet(ctx context.Context, req *connect.Request[pm.DispatchActionSetRequest]) (*connect.Response[pm.DispatchActionSetResponse], error) {
	return s.action.DispatchActionSet(ctx, req)
}

func (s *ControlService) DispatchDefinition(ctx context.Context, req *connect.Request[pm.DispatchDefinitionRequest]) (*connect.Response[pm.DispatchDefinitionResponse], error) {
	return s.action.DispatchDefinition(ctx, req)
}

func (s *ControlService) DispatchToGroup(ctx context.Context, req *connect.Request[pm.DispatchToGroupRequest]) (*connect.Response[pm.DispatchToGroupResponse], error) {
	return s.action.DispatchToGroup(ctx, req)
}

func (s *ControlService) DispatchInstantAction(ctx context.Context, req *connect.Request[pm.DispatchInstantActionRequest]) (*connect.Response[pm.DispatchInstantActionResponse], error) {
	return s.action.DispatchInstantAction(ctx, req)
}

func (s *ControlService) GetExecution(ctx context.Context, req *connect.Request[pm.GetExecutionRequest]) (*connect.Response[pm.GetExecutionResponse], error) {
	return s.action.GetExecution(ctx, req)
}

func (s *ControlService) ListExecutions(ctx context.Context, req *connect.Request[pm.ListExecutionsRequest]) (*connect.Response[pm.ListExecutionsResponse], error) {
	return s.action.ListExecutions(ctx, req)
}

// User Selections
func (s *ControlService) SetUserSelection(ctx context.Context, req *connect.Request[pm.SetUserSelectionRequest]) (*connect.Response[pm.SetUserSelectionResponse], error) {
	return s.userSelection.SetUserSelection(ctx, req)
}

func (s *ControlService) ListAvailableActions(ctx context.Context, req *connect.Request[pm.ListAvailableActionsRequest]) (*connect.Response[pm.ListAvailableActionsResponse], error) {
	return s.userSelection.ListAvailableActions(ctx, req)
}

// Audit Log
func (s *ControlService) ListAuditEvents(ctx context.Context, req *connect.Request[pm.ListAuditEventsRequest]) (*connect.Response[pm.ListAuditEventsResponse], error) {
	return s.audit.ListAuditEvents(ctx, req)
}

// LPS (Local Password Solution)
func (s *ControlService) GetDeviceLpsPasswords(ctx context.Context, req *connect.Request[pm.GetDeviceLpsPasswordsRequest]) (*connect.Response[pm.GetDeviceLpsPasswordsResponse], error) {
	return s.device.GetDeviceLpsPasswords(ctx, req)
}

// LUKS (Disk Encryption)
func (s *ControlService) GetDeviceLuksKeys(ctx context.Context, req *connect.Request[pm.GetDeviceLuksKeysRequest]) (*connect.Response[pm.GetDeviceLuksKeysResponse], error) {
	return s.device.GetDeviceLuksKeys(ctx, req)
}

func (s *ControlService) CreateLuksToken(ctx context.Context, req *connect.Request[pm.CreateLuksTokenRequest]) (*connect.Response[pm.CreateLuksTokenResponse], error) {
	return s.device.CreateLuksToken(ctx, req)
}

func (s *ControlService) RevokeLuksDeviceKey(ctx context.Context, req *connect.Request[pm.RevokeLuksDeviceKeyRequest]) (*connect.Response[pm.RevokeLuksDeviceKeyResponse], error) {
	return s.device.RevokeLuksDeviceKey(ctx, req)
}

// OSQuery / Device Inventory
func (s *ControlService) DispatchOSQuery(ctx context.Context, req *connect.Request[pm.DispatchOSQueryRequest]) (*connect.Response[pm.DispatchOSQueryResponse], error) {
	return s.osquery.DispatchOSQuery(ctx, req)
}

func (s *ControlService) GetOSQueryResult(ctx context.Context, req *connect.Request[pm.GetOSQueryResultRequest]) (*connect.Response[pm.GetOSQueryResultResponse], error) {
	return s.osquery.GetOSQueryResult(ctx, req)
}

func (s *ControlService) GetDeviceInventory(ctx context.Context, req *connect.Request[pm.GetDeviceInventoryRequest]) (*connect.Response[pm.GetDeviceInventoryResponse], error) {
	return s.osquery.GetDeviceInventory(ctx, req)
}

func (s *ControlService) RefreshDeviceInventory(ctx context.Context, req *connect.Request[pm.RefreshDeviceInventoryRequest]) (*connect.Response[pm.RefreshDeviceInventoryResponse], error) {
	return s.osquery.RefreshDeviceInventory(ctx, req)
}

// Device Logs
func (s *ControlService) QueryDeviceLogs(ctx context.Context, req *connect.Request[pm.QueryDeviceLogsRequest]) (*connect.Response[pm.QueryDeviceLogsResponse], error) {
	return s.logs.QueryDeviceLogs(ctx, req)
}

func (s *ControlService) GetDeviceLogResult(ctx context.Context, req *connect.Request[pm.GetDeviceLogResultRequest]) (*connect.Response[pm.GetDeviceLogResultResponse], error) {
	return s.logs.GetDeviceLogResult(ctx, req)
}

// Roles & Permissions
func (s *ControlService) CreateRole(ctx context.Context, req *connect.Request[pm.CreateRoleRequest]) (*connect.Response[pm.CreateRoleResponse], error) {
	return s.role.CreateRole(ctx, req)
}

func (s *ControlService) GetRole(ctx context.Context, req *connect.Request[pm.GetRoleRequest]) (*connect.Response[pm.GetRoleResponse], error) {
	return s.role.GetRole(ctx, req)
}

func (s *ControlService) ListRoles(ctx context.Context, req *connect.Request[pm.ListRolesRequest]) (*connect.Response[pm.ListRolesResponse], error) {
	return s.role.ListRoles(ctx, req)
}

func (s *ControlService) UpdateRole(ctx context.Context, req *connect.Request[pm.UpdateRoleRequest]) (*connect.Response[pm.UpdateRoleResponse], error) {
	return s.role.UpdateRole(ctx, req)
}

func (s *ControlService) DeleteRole(ctx context.Context, req *connect.Request[pm.DeleteRoleRequest]) (*connect.Response[pm.DeleteRoleResponse], error) {
	return s.role.DeleteRole(ctx, req)
}

func (s *ControlService) AssignRoleToUser(ctx context.Context, req *connect.Request[pm.AssignRoleToUserRequest]) (*connect.Response[pm.AssignRoleToUserResponse], error) {
	return s.role.AssignRoleToUser(ctx, req)
}

func (s *ControlService) RevokeRoleFromUser(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserRequest]) (*connect.Response[pm.RevokeRoleFromUserResponse], error) {
	return s.role.RevokeRoleFromUser(ctx, req)
}

func (s *ControlService) ListPermissions(ctx context.Context, req *connect.Request[pm.ListPermissionsRequest]) (*connect.Response[pm.ListPermissionsResponse], error) {
	return s.role.ListPermissions(ctx, req)
}

// User Groups
func (s *ControlService) CreateUserGroup(ctx context.Context, req *connect.Request[pm.CreateUserGroupRequest]) (*connect.Response[pm.CreateUserGroupResponse], error) {
	return s.userGroup.CreateUserGroup(ctx, req)
}

func (s *ControlService) GetUserGroup(ctx context.Context, req *connect.Request[pm.GetUserGroupRequest]) (*connect.Response[pm.GetUserGroupResponse], error) {
	return s.userGroup.GetUserGroup(ctx, req)
}

func (s *ControlService) ListUserGroups(ctx context.Context, req *connect.Request[pm.ListUserGroupsRequest]) (*connect.Response[pm.ListUserGroupsResponse], error) {
	return s.userGroup.ListUserGroups(ctx, req)
}

func (s *ControlService) UpdateUserGroup(ctx context.Context, req *connect.Request[pm.UpdateUserGroupRequest]) (*connect.Response[pm.UpdateUserGroupResponse], error) {
	return s.userGroup.UpdateUserGroup(ctx, req)
}

func (s *ControlService) DeleteUserGroup(ctx context.Context, req *connect.Request[pm.DeleteUserGroupRequest]) (*connect.Response[pm.DeleteUserGroupResponse], error) {
	return s.userGroup.DeleteUserGroup(ctx, req)
}

func (s *ControlService) AddUserToGroup(ctx context.Context, req *connect.Request[pm.AddUserToGroupRequest]) (*connect.Response[pm.AddUserToGroupResponse], error) {
	return s.userGroup.AddUserToGroup(ctx, req)
}

func (s *ControlService) RemoveUserFromGroup(ctx context.Context, req *connect.Request[pm.RemoveUserFromGroupRequest]) (*connect.Response[pm.RemoveUserFromGroupResponse], error) {
	return s.userGroup.RemoveUserFromGroup(ctx, req)
}

func (s *ControlService) AssignRoleToUserGroup(ctx context.Context, req *connect.Request[pm.AssignRoleToUserGroupRequest]) (*connect.Response[pm.AssignRoleToUserGroupResponse], error) {
	return s.userGroup.AssignRoleToUserGroup(ctx, req)
}

func (s *ControlService) RevokeRoleFromUserGroup(ctx context.Context, req *connect.Request[pm.RevokeRoleFromUserGroupRequest]) (*connect.Response[pm.RevokeRoleFromUserGroupResponse], error) {
	return s.userGroup.RevokeRoleFromUserGroup(ctx, req)
}

func (s *ControlService) ListUserGroupsForUser(ctx context.Context, req *connect.Request[pm.ListUserGroupsForUserRequest]) (*connect.Response[pm.ListUserGroupsForUserResponse], error) {
	return s.userGroup.ListUserGroupsForUser(ctx, req)
}

func (s *ControlService) UpdateUserGroupQuery(ctx context.Context, req *connect.Request[pm.UpdateUserGroupQueryRequest]) (*connect.Response[pm.UpdateUserGroupQueryResponse], error) {
	return s.userGroup.UpdateUserGroupQuery(ctx, req)
}

func (s *ControlService) ValidateUserGroupQuery(ctx context.Context, req *connect.Request[pm.ValidateUserGroupQueryRequest]) (*connect.Response[pm.ValidateUserGroupQueryResponse], error) {
	return s.userGroup.ValidateUserGroupQuery(ctx, req)
}

func (s *ControlService) EvaluateDynamicUserGroup(ctx context.Context, req *connect.Request[pm.EvaluateDynamicUserGroupRequest]) (*connect.Response[pm.EvaluateDynamicUserGroupResponse], error) {
	return s.userGroup.EvaluateDynamicUserGroup(ctx, req)
}

// Identity Providers
func (s *ControlService) CreateIdentityProvider(ctx context.Context, req *connect.Request[pm.CreateIdentityProviderRequest]) (*connect.Response[pm.CreateIdentityProviderResponse], error) {
	return s.idp.CreateIdentityProvider(ctx, req)
}

func (s *ControlService) GetIdentityProvider(ctx context.Context, req *connect.Request[pm.GetIdentityProviderRequest]) (*connect.Response[pm.GetIdentityProviderResponse], error) {
	return s.idp.GetIdentityProvider(ctx, req)
}

func (s *ControlService) ListIdentityProviders(ctx context.Context, req *connect.Request[pm.ListIdentityProvidersRequest]) (*connect.Response[pm.ListIdentityProvidersResponse], error) {
	return s.idp.ListIdentityProviders(ctx, req)
}

func (s *ControlService) UpdateIdentityProvider(ctx context.Context, req *connect.Request[pm.UpdateIdentityProviderRequest]) (*connect.Response[pm.UpdateIdentityProviderResponse], error) {
	return s.idp.UpdateIdentityProvider(ctx, req)
}

func (s *ControlService) DeleteIdentityProvider(ctx context.Context, req *connect.Request[pm.DeleteIdentityProviderRequest]) (*connect.Response[pm.DeleteIdentityProviderResponse], error) {
	return s.idp.DeleteIdentityProvider(ctx, req)
}

// SSO
func (s *ControlService) ListAuthMethods(ctx context.Context, req *connect.Request[pm.ListAuthMethodsRequest]) (*connect.Response[pm.ListAuthMethodsResponse], error) {
	return s.sso.ListAuthMethods(ctx, req)
}

func (s *ControlService) GetSSOLoginURL(ctx context.Context, req *connect.Request[pm.GetSSOLoginURLRequest]) (*connect.Response[pm.GetSSOLoginURLResponse], error) {
	return s.sso.GetSSOLoginURL(ctx, req)
}

func (s *ControlService) SSOCallback(ctx context.Context, req *connect.Request[pm.SSOCallbackRequest]) (*connect.Response[pm.SSOCallbackResponse], error) {
	return s.sso.SSOCallback(ctx, req)
}

// Identity Links
func (s *ControlService) ListIdentityLinks(ctx context.Context, req *connect.Request[pm.ListIdentityLinksRequest]) (*connect.Response[pm.ListIdentityLinksResponse], error) {
	return s.identityLink.ListIdentityLinks(ctx, req)
}

func (s *ControlService) UnlinkIdentity(ctx context.Context, req *connect.Request[pm.UnlinkIdentityRequest]) (*connect.Response[pm.UnlinkIdentityResponse], error) {
	return s.identityLink.UnlinkIdentity(ctx, req)
}

// SCIM
func (s *ControlService) EnableSCIM(ctx context.Context, req *connect.Request[pm.EnableSCIMRequest]) (*connect.Response[pm.EnableSCIMResponse], error) {
	return s.idp.EnableSCIM(ctx, req)
}

func (s *ControlService) DisableSCIM(ctx context.Context, req *connect.Request[pm.DisableSCIMRequest]) (*connect.Response[pm.DisableSCIMResponse], error) {
	return s.idp.DisableSCIM(ctx, req)
}

func (s *ControlService) RotateSCIMToken(ctx context.Context, req *connect.Request[pm.RotateSCIMTokenRequest]) (*connect.Response[pm.RotateSCIMTokenResponse], error) {
	return s.idp.RotateSCIMToken(ctx, req)
}

// Device Compliance
func (s *ControlService) GetDeviceCompliance(ctx context.Context, req *connect.Request[pm.GetDeviceComplianceRequest]) (*connect.Response[pm.GetDeviceComplianceResponse], error) {
	return s.compliance.GetDeviceCompliance(ctx, req)
}

// Compliance Policies
func (s *ControlService) CreateCompliancePolicy(ctx context.Context, req *connect.Request[pm.CreateCompliancePolicyRequest]) (*connect.Response[pm.CreateCompliancePolicyResponse], error) {
	return s.compliancePolicy.CreateCompliancePolicy(ctx, req)
}

func (s *ControlService) GetCompliancePolicy(ctx context.Context, req *connect.Request[pm.GetCompliancePolicyRequest]) (*connect.Response[pm.GetCompliancePolicyResponse], error) {
	return s.compliancePolicy.GetCompliancePolicy(ctx, req)
}

func (s *ControlService) ListCompliancePolicies(ctx context.Context, req *connect.Request[pm.ListCompliancePoliciesRequest]) (*connect.Response[pm.ListCompliancePoliciesResponse], error) {
	return s.compliancePolicy.ListCompliancePolicies(ctx, req)
}

func (s *ControlService) RenameCompliancePolicy(ctx context.Context, req *connect.Request[pm.RenameCompliancePolicyRequest]) (*connect.Response[pm.UpdateCompliancePolicyResponse], error) {
	return s.compliancePolicy.RenameCompliancePolicy(ctx, req)
}

func (s *ControlService) UpdateCompliancePolicyDescription(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyDescriptionRequest]) (*connect.Response[pm.UpdateCompliancePolicyResponse], error) {
	return s.compliancePolicy.UpdateCompliancePolicyDescription(ctx, req)
}

func (s *ControlService) DeleteCompliancePolicy(ctx context.Context, req *connect.Request[pm.DeleteCompliancePolicyRequest]) (*connect.Response[pm.DeleteCompliancePolicyResponse], error) {
	return s.compliancePolicy.DeleteCompliancePolicy(ctx, req)
}

func (s *ControlService) AddCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.AddCompliancePolicyRuleRequest]) (*connect.Response[pm.AddCompliancePolicyRuleResponse], error) {
	return s.compliancePolicy.AddCompliancePolicyRule(ctx, req)
}

func (s *ControlService) RemoveCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.RemoveCompliancePolicyRuleRequest]) (*connect.Response[pm.RemoveCompliancePolicyRuleResponse], error) {
	return s.compliancePolicy.RemoveCompliancePolicyRule(ctx, req)
}

func (s *ControlService) UpdateCompliancePolicyRule(ctx context.Context, req *connect.Request[pm.UpdateCompliancePolicyRuleRequest]) (*connect.Response[pm.UpdateCompliancePolicyRuleResponse], error) {
	return s.compliancePolicy.UpdateCompliancePolicyRule(ctx, req)
}

func (s *ControlService) GetDeviceCompliancePolicyStatus(ctx context.Context, req *connect.Request[pm.GetDeviceCompliancePolicyStatusRequest]) (*connect.Response[pm.GetDeviceCompliancePolicyStatusResponse], error) {
	return s.compliancePolicy.GetDeviceCompliancePolicyStatus(ctx, req)
}

// Search
func (s *ControlService) Search(ctx context.Context, req *connect.Request[pm.SearchRequest]) (*connect.Response[pm.SearchResponse], error) {
	return s.search.Search(ctx, req)
}

func (s *ControlService) RebuildSearchIndex(ctx context.Context, req *connect.Request[pm.RebuildSearchIndexRequest]) (*connect.Response[pm.RebuildSearchIndexResponse], error) {
	return s.search.RebuildSearchIndex(ctx, req)
}

// Server Settings
func (s *ControlService) GetServerSettings(ctx context.Context, req *connect.Request[pm.GetServerSettingsRequest]) (*connect.Response[pm.GetServerSettingsResponse], error) {
	return s.settings.GetServerSettings(ctx, req)
}

func (s *ControlService) UpdateServerSettings(ctx context.Context, req *connect.Request[pm.UpdateServerSettingsRequest]) (*connect.Response[pm.UpdateServerSettingsResponse], error) {
	return s.settings.UpdateServerSettings(ctx, req)
}

// User Provisioning Per-User
func (s *ControlService) SetUserProvisioningEnabled(ctx context.Context, req *connect.Request[pm.SetUserProvisioningEnabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.SetUserProvisioningEnabled(ctx, req)
}
