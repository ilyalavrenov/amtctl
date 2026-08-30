package amt

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// bootConfig0 is the instance AMT reserves for one-time boot overrides.
const bootConfig0 = "Intel(r) AMT: Boot Configuration 0"

// isNextSingleUse is the CIM_BootService role for a single boot.
const isNextSingleUse = 1

// amtFirmware is the CIM_SoftwareIdentity instance carrying the AMT version.
const amtFirmware = "AMT"

// Source is a CIM_BootSourceSetting instance ID.
type Source string

const (
	pxe       Source = "Intel(r) AMT: Force PXE Boot"
	hardDrive Source = "Intel(r) AMT: Force Hard-drive Boot"
	cd        Source = "Intel(r) AMT: Force CD/DVD Boot"
)

// PowerState is a CIM_PowerManagementService power transition.
type PowerState int

const (
	powerOn           PowerState = 2
	powerCycleOffHard PowerState = 5
	powerOffHard      PowerState = 8
	masterBusReset    PowerState = 10
)

func StateNames() []string {
	return []string{"on", "off", "reset", "cycle"}
}

func DeviceNames() []string {
	return []string{"pxe", "hdd", "cd"}
}

func ParseDevice(name string) (Source, error) {
	switch name {
	case "pxe":
		return pxe, nil
	case "hdd":
		return hardDrive, nil
	case "cd":
		return cd, nil
	default:
		return "", fmt.Errorf("unknown boot device %q, want %s", name, strings.Join(DeviceNames(), "|"))
	}
}

func ParseState(name string) (PowerState, error) {
	switch name {
	case "on":
		return powerOn, nil
	case "off":
		return powerOffHard, nil
	case "reset":
		return masterBusReset, nil
	case "cycle":
		return powerCycleOffHard, nil
	default:
		return 0, fmt.Errorf("unknown power state %q, want %s", name, strings.Join(StateNames(), "|"))
	}
}

type Client struct {
	endpoint  string
	http      *http.Client
	messageID atomic.Uint64
}

// New builds a client; useTLS selects port 16993 over 16992.
func New(host, user, pass string, useTLS bool) *Client {
	scheme, port := "http", "16992"
	if useTLS {
		scheme, port = "https", "16993"
	}

	return newClient(scheme+"://"+net.JoinHostPort(host, port)+"/wsman", user, pass)
}

// ChangePower errors if AMT accepted the request but refused the transition.
func (c *Client) ChangePower(ctx context.Context, state PowerState) error {
	// AMT exposes one managed system, under a fixed name.
	managed := reference(computerSystemResource,
		selector{Name: "CreationClassName", Value: "CIM_ComputerSystem"},
		selector{Name: "Name", Value: "ManagedSystem"},
	)

	body := requestPowerStateChangeInput{
		H:              powerServiceResource,
		PowerState:     state,
		ManagedElement: managed,
	}

	var res powerChangeResponse

	if err := c.post(ctx, powerServiceResource+"/RequestPowerStateChange", powerServiceResource, body, &res); err != nil {
		return fmt.Errorf("request power state change: %w", err)
	}

	if rv := res.ReturnValue; rv != 0 {
		return fmt.Errorf("power state change rejected: %s", returnValueName(rv))
	}

	return nil
}

func (c *Client) FetchPowerState(ctx context.Context) (string, error) {
	var res powerStateResponse

	if err := c.post(ctx, getAction, associatedPowerResource, nil, &res); err != nil {
		return "", fmt.Errorf("read power state: %w", err)
	}

	return powerStateName(res.PowerState), nil
}

// Info is what a device reports about itself; unreported fields stay empty.
type Info struct {
	Power        string
	Version      string
	Provisioning string
	ControlMode  string
}

func (c *Client) FetchInfo(ctx context.Context) (Info, error) {
	state, err := c.FetchPowerState(ctx)
	if err != nil {
		return Info{}, err
	}

	version, err := c.fetchVersion(ctx)
	if err != nil {
		return Info{}, err
	}

	var setup setupResponse

	if err := c.post(ctx, getAction, setupAndConfigurationResource, nil, &setup); err != nil {
		return Info{}, fmt.Errorf("read setup and configuration: %w", err)
	}

	return Info{
		Power:        state,
		Version:      version,
		Provisioning: provisioning(setup.Service.ProvisioningState),
		ControlMode:  controlMode(setup.Service.ProvisioningMode),
	}, nil
}

// fetchVersion reports the firmware version, or "" when AMT does not list one.
func (c *Client) fetchVersion(ctx context.Context) (string, error) {
	var enumerated enumerateResponse

	body := enumerateInput{XMLNS: enumerationNS}
	if err := c.post(ctx, enumerateAction, softwareIdentityResource, body, &enumerated); err != nil {
		return "", fmt.Errorf("enumerate software identities: %w", err)
	}

	var pulled softwareIdentityResponse

	if err := c.post(ctx, pullAction, softwareIdentityResource, pull(enumerated.Context), &pulled); err != nil {
		return "", fmt.Errorf("read software identities: %w", err)
	}

	for _, item := range pulled.Items {
		if item.InstanceID == amtFirmware {
			return item.VersionString, nil
		}
	}

	return "", nil
}

// AMT_SetupAndConfigurationService.ProvisioningState.
const (
	preProvisioning  = 0
	inProvisioning   = 1
	postProvisioning = 2
)

// provisioning names how far setup has got, or "" for a value AMT has added
// since.
func provisioning(state int) string {
	switch state {
	case preProvisioning:
		return "Pre"
	case inProvisioning:
		return "In"
	case postProvisioning:
		return "Post"
	}

	return ""
}

// AMT_SetupAndConfigurationService.ProvisioningMode. The values are not
// contiguous and 0 means the field was not reported.
const (
	adminControlMode  = 1
	clientControlMode = 4
)

// controlMode names how much of AMT the credentials reach, or "" when the
// device does not report it.
func controlMode(mode int) string {
	switch mode {
	case adminControlMode:
		return "Admin"
	case clientControlMode:
		return "Client"
	}

	return ""
}

// Devices lists the machine's boot sources: ParseDevice names where known, raw
// instance IDs otherwise.
func (c *Client) Devices(ctx context.Context) ([]string, error) {
	var enumerated enumerateResponse

	body := enumerateInput{XMLNS: enumerationNS}
	if err := c.post(ctx, enumerateAction, bootSourceSettingResource, body, &enumerated); err != nil {
		return nil, fmt.Errorf("enumerate boot sources: %w", err)
	}

	var pulled pullResponse

	if err := c.post(ctx, pullAction, bootSourceSettingResource, pull(enumerated.Context), &pulled); err != nil {
		return nil, fmt.Errorf("read boot sources: %w", err)
	}

	names := make([]string, 0, len(pulled.InstanceIDs))
	for _, id := range pulled.InstanceIDs {
		names = append(names, deviceName(id))
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
func (c *Client) ForceBoot(ctx context.Context, device Source, state PowerState) error {
	var current bootSettingsResponse

	if err := c.post(ctx, getAction, bootSettingDataResource, nil, &current); err != nil {
		return fmt.Errorf("read boot settings: %w", err)
	}

	settings := current.Settings

	// Every field left out below stays at its zero value on the wire: media
	// index 0 is the first device of the chosen type, and a boot source rules
	// out the BIOS-screen, IDER and erase options.
	req := bootSettingData{
		H:                    bootSettingDataResource,
		InstanceID:           settings.InstanceID,
		ElementName:          settings.ElementName,
		OwningEntity:         settings.OwningEntity,
		IDERBootDevice:       settings.IDERBootDevice,
		LockKeyboard:         settings.LockKeyboard,
		LockPowerButton:      settings.LockPowerButton,
		LockResetButton:      settings.LockResetButton,
		LockSleepButton:      settings.LockSleepButton,
		FirmwareVerbosity:    settings.FirmwareVerbosity,
		ForcedProgressEvents: settings.ForcedProgressEvents,
		UserPasswordBypass:   settings.UserPasswordBypass,
		UseSafeMode:          settings.UseSafeMode,
		EnforceSecureBoot:    settings.EnforceSecureBoot,
		// Serial console during the forced boot, matching console=ttyS0 kargs.
		UseSOL: true,
	}

	if err := c.post(ctx, putAction, bootSettingDataResource, req, nil); err != nil {
		return fmt.Errorf("write boot settings: %w", err)
	}

	order := changeBootOrderInput{
		H:      bootConfigSettingResource,
		Source: reference(bootSourceSettingResource, instance(string(device))),
	}

	if err := c.post(ctx, bootConfigSettingResource+"/ChangeBootOrder", bootConfigSettingResource, order, nil); err != nil {
		return fmt.Errorf("set boot source: %w", err)
	}

	role := setBootConfigRoleInput{
		H:                 bootServiceResource,
		BootConfigSetting: reference(bootConfigSettingResource, instance(bootConfig0)),
		Role:              isNextSingleUse,
	}

	if err := c.post(ctx, bootServiceResource+"/SetBootConfigRole", bootServiceResource, role, nil); err != nil {
		return fmt.Errorf("arm one-time boot override: %w", err)
	}

	return c.ChangePower(ctx, state)
}

// Event is one decoded record of the AMT hardware event log.
type Event struct {
	Time        time.Time
	Severity    string
	Entity      string
	Description string
}

// AMT_MessageLog.GetRecords return values amtctl acts on.
const (
	recordsRead     = 0
	recordsEmptyLog = 3
)

// Events reads the firmware event log, newest record first. The log survives
// the OS, so it answers why a machine went down.
func (c *Client) Events(ctx context.Context) ([]Event, error) {
	var events []Event

	// AMT ignores PositionToFirstRecord, so the read position goes to GetRecords
	// directly.
	position := 1

	for {
		body := getRecordsInput{
			H:                   messageLogResource,
			IterationIdentifier: position,
			MaxReadRecords:      maxReadRecords,
		}

		var res getRecordsResponse

		if err := c.post(ctx, messageLogResource+"/GetRecords", messageLogResource, body, &res); err != nil {
			return nil, fmt.Errorf("read event log: %w", err)
		}

		records := res.Records

		if rv := records.ReturnValue; rv != recordsRead {
			// An empty log is a return value, not an empty record array.
			if rv == recordsEmptyLog {
				return events, nil
			}

			return nil, fmt.Errorf("read event log: %s", recordsResultName(rv))
		}

		for _, encoded := range records.RecordArray {
			event, err := decodeEvent(encoded)
			if err != nil {
				return nil, fmt.Errorf("read event log: %w", err)
			}

			events = append(events, event)
		}

		// The empty page also stops a device that never sets NoMoreRecords.
		if records.NoMoreRecords || len(records.RecordArray) == 0 {
			return events, nil
		}

		position += len(records.RecordArray)
	}
}

// unknownValue names an enumeration value this build has no name for, keeping
// the number the firmware reported in front of the operator.
func unknownValue(value int) string {
	return "unknown (" + strconv.Itoa(value) + ")"
}

// powerStateName renders CIM_AssociatedPowerManagementService.PowerState, whose
// values run from 1.
func powerStateName(state int) string {
	names := []string{
		"Other", "On", "SleepLight", "SleepDeep", "PowerCycleSoft", "OffHard",
		"Hibernate", "OffSoft", "PowerCycleHard", "MasterBusReset",
		"DiagnosticInterruptNMI", "PowerOffSoftGraceful", "PowerOffHardGraceful",
		"MasterBusResetGraceful", "PowerCycleSoftGraceful", "PowerCycleHardGraceful",
		"DiagnosticInterruptINIT",
	}

	if state < 1 || state > len(names) {
		return unknownValue(state)
	}

	return names[state-1]
}

// jobResultBase is where DMTF's second block of return values starts.
const jobResultBase = 4096

// returnValueName renders a RequestPowerStateChange result.
func returnValueName(value int) string {
	results := []string{
		"CompletedWithNoError", "MethodNotSupported", "UnknownError",
		"CannotCompleteWithinTimeoutPeriod", "Failed", "InvalidParameter", "InUse",
	}
	jobResults := []string{
		"MethodParametersCheckedJobStarted", "InvalidStateTransition",
		"UseOfTimeoutParameterNotSupported", "Busy",
	}

	switch {
	case value >= 0 && value < len(results):
		return results[value]
	case value >= jobResultBase && value < jobResultBase+len(jobResults):
		return jobResults[value-jobResultBase]
	default:
		return unknownValue(value)
	}
}

// recordsResultName renders an AMT_MessageLog.GetRecords result.
func recordsResultName(value int) string {
	names := []string{
		"CompletedWithNoError", "NotSupported", "InvalidRecordPointed", "NoRecordExistsInLog",
	}

	if value < 0 || value >= len(names) {
		return unknownValue(value)
	}

	return names[value]
}
