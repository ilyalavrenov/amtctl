package amt

import (
	"fmt"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	amtboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/setupandconfiguration"
	cimboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

// bootConfig0 is the instance AMT reserves for one-time boot overrides.
const bootConfig0 = "Intel(r) AMT: Boot Configuration 0"

// isNextSingleUse is the CIM_BootService role for a single boot.
const isNextSingleUse = 1

const amtFirmware = "AMT"

const requestTimeout = 30 * time.Second

func StateNames() []string {
	return []string{"on", "off", "reset", "cycle"}
}

func DeviceNames() []string {
	return []string{"pxe", "hdd", "cd"}
}

func ParseDevice(name string) (cimboot.Source, error) {
	switch name {
	case "pxe":
		return cimboot.PXE, nil
	case "hdd":
		return cimboot.HardDrive, nil
	case "cd":
		return cimboot.CD, nil
	default:
		return "", fmt.Errorf("unknown boot device %q, want %s", name, strings.Join(DeviceNames(), "|"))
	}
}

func ParseState(name string) (power.PowerState, error) {
	switch name {
	case "on":
		return power.PowerOn, nil
	case "off":
		return power.PowerOffHard, nil
	case "reset":
		return power.MasterBusReset, nil
	case "cycle":
		return power.PowerCycleOffHard, nil
	default:
		return 0, fmt.Errorf("unknown power state %q, want %s", name, strings.Join(StateNames(), "|"))
	}
}

type Client struct {
	messages wsman.Messages
}

// New builds a client; useTLS selects port 16993 over 16992.
func New(host, user, pass string, useTLS bool) *Client {
	return &Client{messages: wsman.NewMessages(parameters(host, user, pass, useTLS))}
}

// Split from New so tests can inject a Transport; the library hardcodes the port.
func parameters(host, user, pass string, useTLS bool) client.Parameters {
	return client.Parameters{
		Target:            host,
		Username:          user,
		Password:          pass,
		UseDigest:         true,
		UseTLS:            useTLS,
		SelfSignedAllowed: true,
		// The library makes its own context per request, so caller cancellation
		// cannot reach the HTTP call.
		Timeout: requestTimeout,
	}
}

// ChangePower errors if AMT accepted the request but refused the transition.
func (c *Client) ChangePower(state power.PowerState) error {
	res, err := c.messages.CIM.PowerManagementService.RequestPowerStateChange(state)
	if err != nil {
		return fmt.Errorf("request power state change: %w", err)
	}

	if rv := res.Body.RequestPowerStateChangeResponse.ReturnValue; rv != 0 {
		return fmt.Errorf("power state change rejected: %s", rv)
	}

	return nil
}

func (c *Client) FetchPowerState() (string, error) {
	res, err := c.messages.CIM.AssociatedPowerManagementService.Get()
	if err != nil {
		return "", fmt.Errorf("read power state: %w", err)
	}

	return res.Body.AssociatedPowerManagementService.PowerState.String(), nil
}

// Info is what a device reports about itself; unreported fields stay empty.
type Info struct {
	Power        string
	Version      string
	Provisioning string
	ControlMode  string
}

func (c *Client) FetchInfo() (Info, error) {
	state, err := c.FetchPowerState()
	if err != nil {
		return Info{}, err
	}

	version, err := c.fetchVersion()
	if err != nil {
		return Info{}, err
	}

	res, err := c.messages.AMT.SetupAndConfigurationService.Get()
	if err != nil {
		return Info{}, fmt.Errorf("read setup and configuration: %w", err)
	}

	setup := res.Body.GetResponse

	return Info{
		Power:        state,
		Version:      version,
		Provisioning: provisioning(setup.ProvisioningState),
		ControlMode:  controlMode(setup.ProvisioningMode),
	}, nil
}

func (c *Client) fetchVersion() (string, error) {
	enumerated, err := c.messages.CIM.SoftwareIdentity.Enumerate()
	if err != nil {
		return "", fmt.Errorf("enumerate software identities: %w", err)
	}

	pulled, err := c.messages.CIM.SoftwareIdentity.Pull(enumerated.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return "", fmt.Errorf("read software identities: %w", err)
	}

	for _, item := range pulled.Body.PullResponse.SoftwareIdentityItems {
		if item.InstanceID == amtFirmware {
			return item.VersionString, nil
		}
	}

	return "", nil
}

func provisioning(state setupandconfiguration.ProvisioningStateValue) string {
	switch state {
	case setupandconfiguration.PreProvisioning:
		return "Pre"
	case setupandconfiguration.InProvisioning:
		return "In"
	case setupandconfiguration.PostProvisioning:
		return "Post"
	}

	return ""
}

func controlMode(mode setupandconfiguration.ProvisioningModeValue) string {
	switch mode {
	case setupandconfiguration.AdminControlMode:
		return "Admin"
	case setupandconfiguration.ClientControlMode:
		return "Client"
	}

	return ""
}

// Devices lists the machine's boot sources: ParseDevice names where known, raw
// instance IDs otherwise.
func (c *Client) Devices() ([]string, error) {
	enumerated, err := c.messages.CIM.BootSourceSetting.Enumerate()
	if err != nil {
		return nil, fmt.Errorf("enumerate boot sources: %w", err)
	}

	pulled, err := c.messages.CIM.BootSourceSetting.Pull(enumerated.Body.EnumerateResponse.EnumerationContext)
	if err != nil {
		return nil, fmt.Errorf("read boot sources: %w", err)
	}

	items := pulled.Body.PullResponse.BootSourceSettingItems
	names := make([]string, 0, len(items))

	for _, item := range items {
		names = append(names, deviceName(item.InstanceID))
	}

	return names, nil
}

func deviceName(instanceID string) string {
	for _, name := range DeviceNames() {
		if device, err := ParseDevice(name); err == nil && string(device) == instanceID {
			return name
		}
	}

	return instanceID
}

// ForceBoot stages a one-time boot from device, then applies the power action.
// Order matters: settings are consulted only once a boot source is set, and the
// source only takes effect once promoted to next boot.
func (c *Client) ForceBoot(device cimboot.Source, state power.PowerState) error {
	current, err := c.messages.AMT.BootSettingData.Get()
	if err != nil {
		return fmt.Errorf("read boot settings: %w", err)
	}

	settings := current.Body.BootSettingDataGetResponse

	req := amtboot.BootSettingDataRequest{
		InstanceID:     settings.InstanceID,
		ElementName:    settings.ElementName,
		OwningEntity:   settings.OwningEntity,
		IDERBootDevice: settings.IDERBootDevice,
		// 0 is the first device of the chosen type; a boot source rules out
		// the BIOS-screen options.
		BootMediaIndex: 0,
		BIOSPause:      false,
		BIOSSetup:      false,
		ReflashBIOS:    false,
		UseIDER:        false,
		// Serial console during the forced boot, matching console=ttyS0 kargs.
		UseSOL:                 true,
		ConfigurationDataReset: false,
		SecureErase:            false,
		LockKeyboard:           settings.LockKeyboard,
		LockPowerButton:        settings.LockPowerButton,
		LockResetButton:        settings.LockResetButton,
		LockSleepButton:        settings.LockSleepButton,
		FirmwareVerbosity:      settings.FirmwareVerbosity,
		ForcedProgressEvents:   settings.ForcedProgressEvents,
		UserPasswordBypass:     settings.UserPasswordBypass,
		UseSafeMode:            settings.UseSafeMode,
		EnforceSecureBoot:      settings.EnforceSecureBoot,
	}

	if _, err := c.messages.AMT.BootSettingData.Put(req); err != nil {
		return fmt.Errorf("write boot settings: %w", err)
	}

	if _, err := c.messages.CIM.BootConfigSetting.ChangeBootOrder(device); err != nil {
		return fmt.Errorf("set boot source: %w", err)
	}

	if _, err := c.messages.CIM.BootService.SetBootConfigRole(bootConfig0, isNextSingleUse); err != nil {
		return fmt.Errorf("arm one-time boot override: %w", err)
	}

	return c.ChangePower(state)
}
