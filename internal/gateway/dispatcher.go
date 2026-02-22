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

	// Parse notification type
	var basePayload struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(payload), &basePayload); err != nil {
		d.logger.Debug("failed to parse notification payload", "error", err, "payload", payload)
		return
	}

	// Route by notification type
	switch basePayload.Type {
	case "revoke_luks_device_key":
		d.handleRevokeLuksDeviceKey(deviceID, payload)
		return
	case "osquery_dispatch":
		d.handleOSQueryDispatch(deviceID, payload)
		return
	case "request_inventory":
		d.handleRequestInventory(deviceID)
		return
	case "action_dispatch":
		// Continue below
	default:
		d.logger.Debug("ignoring unknown notification type", "type", basePayload.Type)
		return
	}

	var dispatchPayload ActionDispatchPayload
	if err := json.Unmarshal([]byte(payload), &dispatchPayload); err != nil {
		d.logger.Debug("failed to parse action dispatch payload", "error", err, "payload", payload)
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
			Username          string   `json:"username"`
			Uid               int32    `json:"uid"`
			Gid               int32    `json:"gid"`
			HomeDir           string   `json:"homeDir"`
			Shell             string   `json:"shell"`
			SshAuthorizedKeys []string `json:"sshAuthorizedKeys"`
			Comment           string   `json:"comment"`
			SystemUser        bool     `json:"systemUser"`
			CreateHome        bool     `json:"createHome"`
			Disabled          bool     `json:"disabled"`
			PrimaryGroup      string   `json:"primaryGroup"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal user params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_User{
			User: &pm.UserParams{
				Username:          params.Username,
				Uid:               params.Uid,
				Gid:               params.Gid,
				HomeDir:           params.HomeDir,
				Shell:             params.Shell,
				SshAuthorizedKeys: params.SshAuthorizedKeys,
				Comment:           params.Comment,
				SystemUser:        params.SystemUser,
				CreateHome:        params.CreateHome,
				Disabled:          params.Disabled,
				PrimaryGroup:      params.PrimaryGroup,
			},
		}

	case pm.ActionType_ACTION_TYPE_LUKS:
		var params struct {
			PresharedKey             string `json:"presharedKey"`
			RotationIntervalDays     int32  `json:"rotationIntervalDays"`
			MinWords                 int32  `json:"minWords"`
			DeviceBoundKeyType       int32  `json:"deviceBoundKeyType"`
			UserPassphraseMinLength  int32  `json:"userPassphraseMinLength"`
			UserPassphraseComplexity int32  `json:"userPassphraseComplexity"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal luks params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Luks{
			Luks: &pm.LuksParams{
				PresharedKey:             params.PresharedKey,
				RotationIntervalDays:     params.RotationIntervalDays,
				MinWords:                 params.MinWords,
				DeviceBoundKeyType:       pm.LuksDeviceBoundKeyType(params.DeviceBoundKeyType),
				UserPassphraseMinLength:  params.UserPassphraseMinLength,
				UserPassphraseComplexity: pm.LpsPasswordComplexity(params.UserPassphraseComplexity),
			},
		}

	case pm.ActionType_ACTION_TYPE_GROUP:
		var params struct {
			Name        string   `json:"name"`
			Members     []string `json:"members"`
			Gid         int32    `json:"gid"`
			SystemGroup bool     `json:"systemGroup"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal group params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Group{
			Group: &pm.GroupParams{
				Name:        params.Name,
				Members:     params.Members,
				Gid:         params.Gid,
				SystemGroup: params.SystemGroup,
			},
		}

	case pm.ActionType_ACTION_TYPE_SSH:
		var params struct {
			Username      string   `json:"username"`
			AllowPubkey   bool     `json:"allowPubkey"`
			AllowPassword bool     `json:"allowPassword"`
			Users         []string `json:"users"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal ssh params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Ssh{
			Ssh: &pm.SshParams{
				Username:      params.Username,
				AllowPubkey:   params.AllowPubkey,
				AllowPassword: params.AllowPassword,
				Users:         params.Users,
			},
		}

	case pm.ActionType_ACTION_TYPE_SSHD:
		var params struct {
			Priority   uint32 `json:"priority"`
			Directives []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"directives"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal sshd params", "error", err, "action_type", actionTypeName)
			return
		}
		directives := make([]*pm.SshdDirective, len(params.Directives))
		for i, dir := range params.Directives {
			directives[i] = &pm.SshdDirective{
				Key:   dir.Key,
				Value: dir.Value,
			}
		}
		action.Params = &pm.Action_Sshd{
			Sshd: &pm.SshdParams{
				Priority:   params.Priority,
				Directives: directives,
			},
		}

	case pm.ActionType_ACTION_TYPE_SUDO:
		var params struct {
			AccessLevel  int32    `json:"accessLevel"`
			Users        []string `json:"users"`
			CustomConfig string   `json:"customConfig"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal sudo params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Sudo{
			Sudo: &pm.SudoParams{
				AccessLevel:  pm.SudoAccessLevel(params.AccessLevel),
				Users:        params.Users,
				CustomConfig: params.CustomConfig,
			},
		}

	case pm.ActionType_ACTION_TYPE_LPS:
		var params struct {
			Usernames            []string `json:"usernames"`
			PasswordLength       int32    `json:"passwordLength"`
			Complexity           int32    `json:"complexity"`
			RotationIntervalDays int32    `json:"rotationIntervalDays"`
			GracePeriodHours     int32    `json:"gracePeriodHours"`
		}
		if err := json.Unmarshal(paramsJSON, &params); err != nil {
			d.logger.Debug("failed to unmarshal lps params", "error", err, "action_type", actionTypeName)
			return
		}
		action.Params = &pm.Action_Lps{
			Lps: &pm.LpsParams{
				Usernames:            params.Usernames,
				PasswordLength:       params.PasswordLength,
				Complexity:           pm.LpsPasswordComplexity(params.Complexity),
				RotationIntervalDays: params.RotationIntervalDays,
				GracePeriodHours:     params.GracePeriodHours,
			},
		}

	default:
		d.logger.Debug("unknown action type, no params to parse", "action_type", actionTypeName)
	}
}

// handleRevokeLuksDeviceKey dispatches a LUKS device key revocation to the connected agent.
func (d *Dispatcher) handleRevokeLuksDeviceKey(deviceID, payload string) {
	var revokePayload struct {
		ActionID string `json:"action_id"`
	}
	if err := json.Unmarshal([]byte(payload), &revokePayload); err != nil {
		d.logger.Debug("failed to parse revoke LUKS payload", "error", err)
		return
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RevokeLuksDeviceKey{
			RevokeLuksDeviceKey: &pm.RevokeLuksDeviceKey{
				ActionId: revokePayload.ActionID,
			},
		},
	}

	if err := d.manager.Send(deviceID, msg); err != nil {
		d.logger.Error("failed to send LUKS revocation to agent",
			"device_id", deviceID,
			"action_id", revokePayload.ActionID,
			"error", err,
		)
		return
	}

	d.logger.Info("LUKS device key revocation dispatched",
		"device_id", deviceID,
		"action_id", revokePayload.ActionID,
	)
}

// handleOSQueryDispatch dispatches an on-demand OSQuery to the connected agent.
func (d *Dispatcher) handleOSQueryDispatch(deviceID, payload string) {
	var queryPayload struct {
		QueryID string   `json:"query_id"`
		Table   string   `json:"table"`
		Columns []string `json:"columns"`
		Limit   int32    `json:"limit"`
		RawSQL  string   `json:"raw_sql"`
	}
	if err := json.Unmarshal([]byte(payload), &queryPayload); err != nil {
		d.logger.Debug("failed to parse osquery dispatch payload", "error", err)
		return
	}

	query := &pm.OSQuery{
		QueryId: queryPayload.QueryID,
		Table:   queryPayload.Table,
		Columns: queryPayload.Columns,
		Limit:   queryPayload.Limit,
		RawSql:  queryPayload.RawSQL,
	}

	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_Query{
			Query: query,
		},
	}

	if err := d.manager.Send(deviceID, msg); err != nil {
		d.logger.Error("failed to send osquery to agent",
			"device_id", deviceID,
			"query_id", queryPayload.QueryID,
			"error", err,
		)
		return
	}

	d.logger.Info("osquery dispatched",
		"device_id", deviceID,
		"query_id", queryPayload.QueryID,
		"table", queryPayload.Table,
	)
}

// handleRequestInventory asks the agent to re-collect and send device inventory.
func (d *Dispatcher) handleRequestInventory(deviceID string) {
	msg := &pm.ServerMessage{
		Id: ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String(),
		Payload: &pm.ServerMessage_RequestInventory{
			RequestInventory: &pm.RequestInventory{},
		},
	}

	if err := d.manager.Send(deviceID, msg); err != nil {
		d.logger.Error("failed to send inventory request to agent",
			"device_id", deviceID,
			"error", err,
		)
		return
	}

	d.logger.Info("inventory request dispatched", "device_id", deviceID)
}
