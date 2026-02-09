package api

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/ca"
	"github.com/manchtools/power-manage/server/internal/store"
)

// ControlService implements the ControlService Connect-RPC service.
type ControlService struct {
	registration  *RegistrationHandler
	auth          *AuthHandler
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
}

// NewControlService creates a new control service.
func NewControlService(st *store.Store, jwtManager *auth.JWTManager, signer ActionSigner, certAuth *ca.CA, gatewayURL string, logger *slog.Logger) *ControlService {
	actionHandler := NewActionHandler(st, signer)
	return &ControlService{
		registration:  NewRegistrationHandler(st, certAuth, gatewayURL, logger),
		auth:          NewAuthHandler(st, jwtManager),
		user:          NewUserHandler(st),
		device:        NewDeviceHandler(st),
		token:         NewTokenHandler(st),
		action:        actionHandler,
		actionSet:     NewActionSetHandler(st),
		definition:    NewDefinitionHandler(st),
		deviceGroup:   NewDeviceGroupHandler(st),
		assignment:    NewAssignmentHandler(st, actionHandler),
		userSelection: NewUserSelectionHandler(st),
		audit:         NewAuditHandler(st),
	}
}

var _ pmv1connect.ControlServiceHandler = (*ControlService)(nil)

// Agent Registration
func (s *ControlService) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	return s.registration.Register(ctx, req)
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

func (s *ControlService) UpdateUserRole(ctx context.Context, req *connect.Request[pm.UpdateUserRoleRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.UpdateUserRole(ctx, req)
}

func (s *ControlService) SetUserDisabled(ctx context.Context, req *connect.Request[pm.SetUserDisabledRequest]) (*connect.Response[pm.UpdateUserResponse], error) {
	return s.user.SetUserDisabled(ctx, req)
}

func (s *ControlService) DeleteUser(ctx context.Context, req *connect.Request[pm.DeleteUserRequest]) (*connect.Response[pm.DeleteUserResponse], error) {
	return s.user.DeleteUser(ctx, req)
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
