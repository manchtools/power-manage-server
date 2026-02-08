// Package gateway handles action dispatch from control server to connected agents.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/server/internal/connection"
	"github.com/manchtools/power-manage/server/internal/store"
)

// Dispatcher listens for action dispatch notifications and forwards them to connected agents.
type Dispatcher struct {
	store   *store.Store
	manager *connection.Manager
	logger  *slog.Logger
}

// NewDispatcher creates a new dispatcher.
func NewDispatcher(s *store.Store, m *connection.Manager, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		store:   s,
		manager: m,
		logger:  logger,
	}
}

// Run starts listening for agent notifications.
// This method blocks until the context is cancelled.
func (d *Dispatcher) Run(ctx context.Context) error {
	d.logger.Info("starting gateway dispatcher, listening on agent_* channels")

	// Listen for notifications on all agent channels
	if err := d.store.Listen(ctx, "agent_*", func(channel, payload string) {
		// Extract device ID from channel name (agent_<device_id>)
		if !strings.HasPrefix(channel, "agent_") {
			return
		}
		deviceID := strings.TrimPrefix(channel, "agent_")

		d.logger.Debug("received notification",
			"channel", channel,
			"device_id", deviceID,
			"payload_length", len(payload),
		)

		d.handleNotification(ctx, deviceID, payload)
	}); err != nil {
		return err
	}

	d.logger.Debug("listener started, waiting for notifications")

	// Block until context is cancelled
	<-ctx.Done()
	return ctx.Err()
}

// ActionDispatchPayload represents the notification payload from control server.
type ActionDispatchPayload struct {
	Type           string          `json:"type"`
	ExecutionID    string          `json:"execution_id"`
	ActionType     int32           `json:"action_type"`
	DesiredState   int32           `json:"desired_state"`
	Params         json.RawMessage `json:"params"`
	TimeoutSeconds int32           `json:"timeout_seconds"`
}

func (d *Dispatcher) handleNotification(ctx context.Context, deviceID, payload string) {
	// Check if agent is connected
	if !d.manager.IsConnected(deviceID) {
		d.logger.Debug("agent not connected, ignoring notification", "device_id", deviceID)
		return
	}

	// Try to parse as action dispatch
	var dispatchPayload ActionDispatchPayload
	if err := json.Unmarshal([]byte(payload), &dispatchPayload); err != nil {
		d.logger.Debug("failed to parse notification payload", "error", err, "payload", payload)
		return
	}

	// Only handle action_dispatch messages
	if dispatchPayload.Type != "action_dispatch" {
		d.logger.Debug("ignoring non-dispatch notification", "type", dispatchPayload.Type)
		return
	}

	d.logger.Info("dispatching action to agent",
		"device_id", deviceID,
		"execution_id", dispatchPayload.ExecutionID,
		"action_type", dispatchPayload.ActionType,
	)

	// Build the Action message
	action := &pm.Action{
		Id:             &pm.ActionId{Value: dispatchPayload.ExecutionID},
		Type:           pm.ActionType(dispatchPayload.ActionType),
		DesiredState:   pm.DesiredState(dispatchPayload.DesiredState),
		TimeoutSeconds: dispatchPayload.TimeoutSeconds,
	}

	// Parse params based on action type
	if len(dispatchPayload.Params) > 0 && string(dispatchPayload.Params) != "null" && string(dispatchPayload.Params) != "{}" {
		d.parseActionParams(action, dispatchPayload.ActionType, dispatchPayload.Params)
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

	// Send to agent
	if err := d.manager.Send(deviceID, msg); err != nil {
		d.logger.Error("failed to send action to agent",
			"device_id", deviceID,
			"execution_id", dispatchPayload.ExecutionID,
			"error", err,
		)
		return
	}

	d.logger.Info("action dispatched successfully",
		"device_id", deviceID,
		"execution_id", dispatchPayload.ExecutionID,
		"action_type", pm.ActionType(dispatchPayload.ActionType).String(),
	)
}

// parseActionParams populates the oneof Params field on an Action from JSON.
func (d *Dispatcher) parseActionParams(action *pm.Action, actionType int32, paramsJSON []byte) {
	actionTypeName := pm.ActionType(actionType).String()

	switch pm.ActionType(actionType) {
	case pm.ActionType_ACTION_TYPE_PACKAGE:
		var params struct {
			Name           string `json:"name"`
			Version        string `json:"version"`
			Pin            bool   `json:"pin"`
			AllowDowngrade bool   `json:"allowDowngrade"`
			AptName        string `json:"aptName"`
			DnfName        string `json:"dnfName"`
			PacmanName     string `json:"pacmanName"`
			ZypperName     string `json:"zypperName"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal package params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Package{
			Package: &pm.PackageParams{
				Name:           params.Name,
				Version:        params.Version,
				Pin:            params.Pin,
				AllowDowngrade: params.AllowDowngrade,
				AptName:        params.AptName,
				DnfName:        params.DnfName,
				PacmanName:     params.PacmanName,
				ZypperName:     params.ZypperName,
			},
		}

	case pm.ActionType_ACTION_TYPE_APP_IMAGE, pm.ActionType_ACTION_TYPE_DEB, pm.ActionType_ACTION_TYPE_RPM:
		var params struct {
			URL            string `json:"url"`
			ChecksumSha256 string `json:"checksumSha256"`
			InstallPath    string `json:"installPath"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal app params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_App{
			App: &pm.AppInstallParams{
				Url:            params.URL,
				ChecksumSha256: params.ChecksumSha256,
				InstallPath:    params.InstallPath,
			},
		}

	case pm.ActionType_ACTION_TYPE_FLATPAK:
		var params struct {
			AppId      string `json:"appId"`
			Remote     string `json:"remote"`
			SystemWide bool   `json:"systemWide"`
			Pin        bool   `json:"pin"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal flatpak params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Flatpak{
			Flatpak: &pm.FlatpakParams{
				AppId:      params.AppId,
				Remote:     params.Remote,
				SystemWide: params.SystemWide,
				Pin:        params.Pin,
			},
		}

	case pm.ActionType_ACTION_TYPE_SHELL:
		var params struct {
			Script           string            `json:"script"`
			Interpreter      string            `json:"interpreter"`
			RunAsRoot        bool              `json:"runAsRoot"`
			WorkingDirectory string            `json:"workingDirectory"`
			Environment      map[string]string `json:"environment"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal shell params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Shell{
			Shell: &pm.ShellParams{
				Script:           params.Script,
				Interpreter:      params.Interpreter,
				RunAsRoot:        params.RunAsRoot,
				WorkingDirectory: params.WorkingDirectory,
				Environment:      params.Environment,
			},
		}

	case pm.ActionType_ACTION_TYPE_SYSTEMD:
		var params struct {
			UnitName     string          `json:"unitName"`
			UnitContent  string          `json:"unitContent"`
			Enable       bool            `json:"enable"`
			DesiredState json.RawMessage `json:"desiredState"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal systemd params", "error", err, "action_type", actionTypeName)
			return
		}
		var desiredState pm.SystemdUnitState
		if len(params.DesiredState) > 0 {
			var stateInt int32
			if err := json.Unmarshal(params.DesiredState, &stateInt); err == nil {
				desiredState = pm.SystemdUnitState(stateInt)
			} else {
				var stateStr string
				if err := json.Unmarshal(params.DesiredState, &stateStr); err == nil {
					if val, ok := pm.SystemdUnitState_value[stateStr]; ok {
						desiredState = pm.SystemdUnitState(val)
					}
				} else {
					d.logger.Debug("failed to parse systemd desired state", "error", err, "raw", string(params.DesiredState))
				}
			}
		}
		action.Params = &pm.Action_Systemd{
			Systemd: &pm.SystemdParams{
				UnitName:     params.UnitName,
				UnitContent:  params.UnitContent,
				Enable:       params.Enable,
				DesiredState: desiredState,
			},
		}

	case pm.ActionType_ACTION_TYPE_FILE:
		var params struct {
			Path    string `json:"path"`
			Content string `json:"content"`
			Mode    string `json:"mode"`
			Owner   string `json:"owner"`
			Group   string `json:"group"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal file params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_File{
			File: &pm.FileParams{
				Path:    params.Path,
				Content: params.Content,
				Mode:    params.Mode,
				Owner:   params.Owner,
				Group:   params.Group,
			},
		}

	case pm.ActionType_ACTION_TYPE_UPDATE:
		var params struct {
			SecurityOnly     bool `json:"securityOnly"`
			Autoremove       bool `json:"autoremove"`
			RebootIfRequired bool `json:"rebootIfRequired"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal update params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Update{
			Update: &pm.UpdateParams{
				SecurityOnly:     params.SecurityOnly,
				Autoremove:       params.Autoremove,
				RebootIfRequired: params.RebootIfRequired,
			},
		}

	case pm.ActionType_ACTION_TYPE_REPOSITORY:
		var params struct {
			Name   string `json:"name"`
			Apt    *struct {
				Url          string   `json:"url"`
				Distribution string   `json:"distribution"`
				Components   []string `json:"components"`
				GpgKeyUrl    string   `json:"gpgKeyUrl"`
				GpgKey       string   `json:"gpgKey"`
				Trusted      bool     `json:"trusted"`
				Arch         string   `json:"arch"`
				Disabled     bool     `json:"disabled"`
			} `json:"apt"`
			Dnf *struct {
				Baseurl        string `json:"baseurl"`
				Description    string `json:"description"`
				Enabled        bool   `json:"enabled"`
				Gpgcheck       bool   `json:"gpgcheck"`
				Gpgkey         string `json:"gpgkey"`
				ModuleHotfixes bool   `json:"moduleHotfixes"`
				Disabled       bool   `json:"disabled"`
			} `json:"dnf"`
			Pacman *struct {
				Server   string `json:"server"`
				SigLevel string `json:"sigLevel"`
				Disabled bool   `json:"disabled"`
			} `json:"pacman"`
			Zypper *struct {
				Url         string `json:"url"`
				Description string `json:"description"`
				Enabled     bool   `json:"enabled"`
				Autorefresh bool   `json:"autorefresh"`
				Gpgcheck    bool   `json:"gpgcheck"`
				Gpgkey      string `json:"gpgkey"`
				Type        string `json:"type"`
				Disabled    bool   `json:"disabled"`
			} `json:"zypper"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal repository params", "error", err, "action_type", actionTypeName)
			return
		}
		repoParams := &pm.RepositoryParams{
			Name: params.Name,
		}
		if params.Apt != nil {
			repoParams.Apt = &pm.AptRepository{
				Url:          params.Apt.Url,
				Distribution: params.Apt.Distribution,
				Components:   params.Apt.Components,
				GpgKeyUrl:    params.Apt.GpgKeyUrl,
				GpgKey:       params.Apt.GpgKey,
				Trusted:      params.Apt.Trusted,
				Arch:         params.Apt.Arch,
				Disabled:     params.Apt.Disabled,
			}
		}
		if params.Dnf != nil {
			repoParams.Dnf = &pm.DnfRepository{
				Baseurl:        params.Dnf.Baseurl,
				Description:    params.Dnf.Description,
				Enabled:        params.Dnf.Enabled,
				Gpgcheck:       params.Dnf.Gpgcheck,
				Gpgkey:         params.Dnf.Gpgkey,
				ModuleHotfixes: params.Dnf.ModuleHotfixes,
				Disabled:       params.Dnf.Disabled,
			}
		}
		if params.Pacman != nil {
			repoParams.Pacman = &pm.PacmanRepository{
				Server:   params.Pacman.Server,
				SigLevel: params.Pacman.SigLevel,
				Disabled: params.Pacman.Disabled,
			}
		}
		if params.Zypper != nil {
			repoParams.Zypper = &pm.ZypperRepository{
				Url:         params.Zypper.Url,
				Description: params.Zypper.Description,
				Enabled:     params.Zypper.Enabled,
				Autorefresh: params.Zypper.Autorefresh,
				Gpgcheck:    params.Zypper.Gpgcheck,
				Gpgkey:      params.Zypper.Gpgkey,
				Type:        params.Zypper.Type,
				Disabled:    params.Zypper.Disabled,
			}
		}
		action.Params = &pm.Action_Repository{
			Repository: repoParams,
		}

	case pm.ActionType_ACTION_TYPE_DIRECTORY:
		var params struct {
			Path      string `json:"path"`
			Owner     string `json:"owner"`
			Group     string `json:"group"`
			Mode      string `json:"mode"`
			Recursive bool   `json:"recursive"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal directory params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Directory{
			Directory: &pm.DirectoryParams{
				Path:      params.Path,
				Owner:     params.Owner,
				Group:     params.Group,
				Mode:      params.Mode,
				Recursive: params.Recursive,
			},
		}

	case pm.ActionType_ACTION_TYPE_USER:
		var params struct {
			Username     string   `json:"username"`
			Uid          int32    `json:"uid"`
			Gid          int32    `json:"gid"`
			HomeDir      string   `json:"homeDir"`
			Shell        string   `json:"shell"`
			Groups       []string `json:"groups"`
			Comment      string   `json:"comment"`
			SystemUser   bool     `json:"systemUser"`
			CreateHome   bool     `json:"createHome"`
			Disabled     bool     `json:"disabled"`
			PrimaryGroup string   `json:"primaryGroup"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal user params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_User{
			User: &pm.UserParams{
				Username:     params.Username,
				Uid:          params.Uid,
				Gid:          params.Gid,
				HomeDir:      params.HomeDir,
				Shell:        params.Shell,
				Groups:       params.Groups,
				Comment:      params.Comment,
				SystemUser:   params.SystemUser,
				CreateHome:   params.CreateHome,
				Disabled:     params.Disabled,
				PrimaryGroup: params.PrimaryGroup,
			},
		}

	default:
		d.logger.Debug("unknown action type, no params to parse", "action_type", actionTypeName)
	}
}
