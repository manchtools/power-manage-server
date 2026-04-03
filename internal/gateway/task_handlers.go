package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/encoding/protojson"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/taskqueue"
)

// UpdateInfoProvider fetches auto-update info from the control server.
type UpdateInfoProvider interface {
	GetAutoUpdateInfo(ctx context.Context, agentArch string) (*pm.GetAutoUpdateInfoResponse, error)
}

// TaskHandlerFactory creates per-device Asynq ServeMux instances.
type TaskHandlerFactory struct {
	manager        *connection.Manager
	updateProvider UpdateInfoProvider
	serverVersion  string
	logger         *slog.Logger
}

// NewTaskHandlerFactory creates a new factory.
func NewTaskHandlerFactory(manager *connection.Manager, updateProvider UpdateInfoProvider, serverVersion string, logger *slog.Logger) *TaskHandlerFactory {
	return &TaskHandlerFactory{
		manager:        manager,
		updateProvider: updateProvider,
		serverVersion:  serverVersion,
		logger:         logger,
	}
}

// NewMux returns a handler factory function for DeviceWorkerManager.
func (f *TaskHandlerFactory) NewMux(deviceID string) *asynq.ServeMux {
	h := &deviceTaskHandler{
		deviceID:       deviceID,
		manager:        f.manager,
		updateProvider: f.updateProvider,
		serverVersion:  f.serverVersion,
		logger:         f.logger.With("device_id", deviceID),
	}

	mux := asynq.NewServeMux()
	mux.HandleFunc(taskqueue.TypeActionDispatch, h.handleActionDispatch)
	mux.HandleFunc(taskqueue.TypeOSQueryDispatch, h.handleOSQueryDispatch)
	mux.HandleFunc(taskqueue.TypeInventoryRequest, h.handleInventoryRequest)
	mux.HandleFunc(taskqueue.TypeRevokeLuksDeviceKey, h.handleRevokeLuksDeviceKey)
	mux.HandleFunc(taskqueue.TypeLogQueryDispatch, h.handleLogQueryDispatch)
	mux.HandleFunc(taskqueue.TypeTriggerUpdate, h.handleTriggerUpdate)
	return mux
}

// deviceTaskHandler processes tasks from a specific device's queue.
type deviceTaskHandler struct {
	deviceID       string
	manager        *connection.Manager
	updateProvider UpdateInfoProvider
	serverVersion  string
	logger         *slog.Logger
}

func (h *deviceTaskHandler) handleActionDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.ActionDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal action dispatch: %w", err)
	}

	h.logger.Info("dispatching action to agent",
		"execution_id", payload.ExecutionID,
		"action_type", payload.ActionType,
	)

	// Build Action message
	action := &pm.Action{
		Id:              &pm.ActionId{Value: payload.ExecutionID},
		Type:            pm.ActionType(payload.ActionType),
		DesiredState:    pm.DesiredState(payload.DesiredState),
		TimeoutSeconds:  payload.TimeoutSeconds,
		Signature:       payload.Signature,
		ParamsCanonical: payload.ParamsCanonical,
	}

	// Parse params
	if len(payload.Params) > 0 && string(payload.Params) != "null" && string(payload.Params) != "{}" {
		parseActionParams(action, payload.ActionType, payload.Params)
	}

	// Wrap in ServerMessage
	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Action{
			Action: &pm.ActionDispatch{
				Action: action,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send action to agent: %w", err)
	}

	h.logger.Info("action dispatched successfully",
		"execution_id", payload.ExecutionID,
		"action_type", pm.ActionType(payload.ActionType).String(),
	)
	return nil
}

func (h *deviceTaskHandler) handleOSQueryDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.OSQueryDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal osquery dispatch: %w", err)
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Query{
			Query: &pm.OSQuery{
				QueryId: payload.QueryID,
				Table:   payload.Table,
				Columns: payload.Columns,
				Limit:   payload.Limit,
				RawSql:  payload.RawSQL,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send osquery to agent: %w", err)
	}

	h.logger.Info("osquery dispatched", "query_id", payload.QueryID, "table", payload.Table)
	return nil
}

func (h *deviceTaskHandler) handleInventoryRequest(_ context.Context, _ *asynq.Task) error {
	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: &pm.RequestInventory{},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send inventory request to agent: %w", err)
	}

	h.logger.Info("inventory request dispatched")
	return nil
}

func (h *deviceTaskHandler) handleRevokeLuksDeviceKey(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.RevokeLuksDeviceKeyPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal revoke luks: %w", err)
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{
				ActionId: payload.ActionID,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send LUKS revocation to agent: %w", err)
	}

	h.logger.Info("LUKS device key revocation dispatched", "action_id", payload.ActionID)
	return nil
}

func (h *deviceTaskHandler) handleLogQueryDispatch(_ context.Context, t *asynq.Task) error {
	var payload taskqueue.LogQueryDispatchPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal log query dispatch: %w", err)
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_LogQuery{
			LogQuery: &pm.LogQuery{
				QueryId:  payload.QueryID,
				Lines:    payload.Lines,
				Unit:     payload.Unit,
				Since:    payload.Since,
				Until:    payload.Until,
				Priority: payload.Priority,
				Grep:     payload.Grep,
				Kernel:   payload.Kernel,
			},
		},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send log query to agent: %w", err)
	}

	h.logger.Info("log query dispatched", "query_id", payload.QueryID, "unit", payload.Unit)
	return nil
}

func (h *deviceTaskHandler) handleTriggerUpdate(ctx context.Context, _ *asynq.Task) error {
	// Fetch latest update info from control server.
	updateInfo, err := h.updateProvider.GetAutoUpdateInfo(ctx, "amd64")
	if err != nil {
		return fmt.Errorf("get auto-update info: %w", err)
	}

	welcome := &pm.Welcome{
		ServerVersion: h.serverVersion,
	}
	if updateInfo.LatestAgentVersion != "" {
		welcome.LatestAgentVersion = updateInfo.LatestAgentVersion
		welcome.UpdateUrl = updateInfo.UpdateUrl
		welcome.UpdateChecksum = updateInfo.UpdateChecksum
	}

	msg := &pm.ServerMessage{
		Id:      ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Welcome{Welcome: welcome},
	}

	if err := h.manager.Send(h.deviceID, msg); err != nil {
		return fmt.Errorf("send update welcome to agent: %w", err)
	}

	h.logger.Info("agent update triggered", "latest_version", updateInfo.LatestAgentVersion)
	return nil
}

// parseActionParams populates the oneof Params field on an Action from JSON.
func parseActionParams(action *pm.Action, actionType int32, paramsJSON []byte) {
	unmarshal := protojson.UnmarshalOptions{DiscardUnknown: true}

	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var p pm.PackageParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Package{Package: &p}
		}
	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var p pm.AppInstallParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_App{App: &p}
		}
	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var p pm.FlatpakParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Flatpak{Flatpak: &p}
		}
	case pm.ActionType_ACTION_TYPE_SHELL, pm.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var p pm.ShellParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Shell{Shell: &p}
		}
	case pm.ActionType_ACTION_TYPE_SYSTEMD:
		var p pm.SystemdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Systemd{Systemd: &p}
		}
	case pm.ActionType_ACTION_TYPE_FILE:
		var p pm.FileParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_File{File: &p}
		}
	case pm.ActionType_ACTION_TYPE_UPDATE:
		var p pm.UpdateParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Update{Update: &p}
		}
	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var p pm.RepositoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Repository{Repository: &p}
		}
	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var p pm.DirectoryParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Directory{Directory: &p}
		}
	case pm.ActionType_ACTION_TYPE_USER:
		var p pm.UserParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_User{User: &p}
		}
	case pm.ActionType_ACTION_TYPE_GROUP:
		var p pm.GroupParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Group{Group: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSH:
		var p pm.SshParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Ssh{Ssh: &p}
		}
	case pm.ActionType_ACTION_TYPE_SSHD:
		var p pm.SshdParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sshd{Sshd: &p}
		}
	case pm.ActionType_ACTION_TYPE_SUDO:
		var p pm.SudoParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Sudo{Sudo: &p}
		}
	case pm.ActionType_ACTION_TYPE_LPS:
		var p pm.LpsParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Lps{Lps: &p}
		}
	case pm.ActionType_ACTION_TYPE_LUKS:
		var p pm.LuksParams
		if err := unmarshal.Unmarshal(paramsJSON, &p); err == nil {
			action.Params = &pm.Action_Luks{Luks: &p}
		}
	}
}
