package amt

import (
	"fmt"
	"strings"
	"time"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	amtboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/boot"
	cimboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/client"
)

// bootConfig0 is the instance AMT reserves for one-time boot overrides.
const bootConfig0 = "Intel(r) AMT: Boot Configuration 0"

// isNextSingleUse is the CIM_BootService role for a single boot.
const isNextSingleUse = 1

const requestTimeout = 30 * time.Second

type PowerState = power.PowerState

func StateNames() []string {
	return []string{"on", "off", "reset", "cycle"}
}

func ParseState(name string) (PowerState, error) {
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
func (c *Client) ChangePower(state PowerState) error {
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

// ForcePXE stages a one-time PXE boot, then applies the power action. Order
// matters: settings are consulted only once a boot source is set, and the source
// only takes effect once promoted to next boot.
func (c *Client) ForcePXE(state PowerState) error {
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
		// PXE requires index 0, and a boot source rules out the BIOS-screen
		// options.
		BootMediaIndex: 0,
		BIOSPause:      false,
		BIOSSetup:      false,
		ReflashBIOS:    false,
		UseIDER:        false,
		// Serial console during the PXE boot, matching console=ttyS0 kargs.
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

	if _, err := c.messages.CIM.BootConfigSetting.ChangeBootOrder(cimboot.PXE); err != nil {
		return fmt.Errorf("set PXE boot source: %w", err)
	}

	if _, err := c.messages.CIM.BootService.SetBootConfigRole(bootConfig0, isNextSingleUse); err != nil {
		return fmt.Errorf("arm one-time boot override: %w", err)
	}

	return c.ChangePower(state)
}
