package amt

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman"
	cimboot "github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/boot"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/cim/power"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// device is a fake AMT WSMAN endpoint: canned SOAP responses, calls recorded in
// order.
type device struct {
	// powerReturn is the ReturnValue answered to RequestPowerStateChange.
	powerReturn int
	// reject names one call to answer with an error instead of a result.
	reject string
	sparse bool

	mu     sync.Mutex
	calls  []string
	bodies map[string]string
}

// serve starts the device and returns a client wired to it.
func (d *device) serve(t *testing.T) *Client {
	t.Helper()

	d.bodies = make(map[string]string)

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)

	// A distinct target per test keeps the library's per-host connection limiter
	// from coupling parallel tests.
	params := parameters(strings.ReplaceAll(t.Name(), "/", "-"), "admin", "secret", false)
	params.Transport = redirect{srv.Listener.Addr().String()}

	return &Client{messages: wsman.NewMessages(params)}
}

func (d *device) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	var req struct {
		Action      string `xml:"Header>Action"`
		ResourceURI string `xml:"Header>ResourceURI"`
	}

	if err := xml.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	call := path.Base(req.ResourceURI) + "." + path.Base(req.Action)

	d.mu.Lock()
	d.calls = append(d.calls, call)
	d.bodies[call] = string(body)
	d.mu.Unlock()

	reply, ok := d.answer(call)
	if !ok || call == d.reject {
		http.Error(w, "device refused "+call, http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	_, _ = io.WriteString(w, reply)
}

// answer is the canned response for one call. Only the calls whose result is
// read carry content.
func (d *device) answer(call string) (string, bool) {
	switch call {
	case "AMT_BootSettingData.Get":
		// Set here so the Put has to be seen clearing them, not echoing.
		return envelope(`<AMT_BootSettingData>` +
			`<InstanceID>Intel(r) AMT:BootSettingData 0</InstanceID>` +
			`<ElementName>Boot Configuration</ElementName>` +
			`<BIOSSetup>true</BIOSSetup>` +
			`<BootMediaIndex>2</BootMediaIndex>` +
			`<LockKeyboard>true</LockKeyboard>` +
			`</AMT_BootSettingData>`), true
	case "AMT_BootSettingData.Put", "CIM_BootConfigSetting.ChangeBootOrder", "CIM_BootService.SetBootConfigRole":
		return envelope(""), true
	case "CIM_BootSourceSetting.Enumerate":
		return envelope("<EnumerateResponse><EnumerationContext>ctx</EnumerationContext></EnumerateResponse>"), true
	case "CIM_BootSourceSetting.Pull":
		// One source with no short name, so the raw instance ID has to survive.
		return envelope("<PullResponse><Items>" +
			sourceItem("Intel(r) AMT: Force PXE Boot") +
			sourceItem("Intel(r) AMT: Force Hard-drive Boot") +
			sourceItem("Intel(r) AMT: Force OCR UEFI HTTPS Boot") +
			"</Items></PullResponse>"), true
	case "CIM_AssociatedPowerManagementService.Get":
		return envelope("<CIM_AssociatedPowerManagementService><PowerState>2</PowerState>" +
			"</CIM_AssociatedPowerManagementService>"), true
	case "AMT_SetupAndConfigurationService.Get":
		mode := "<ProvisioningMode>1</ProvisioningMode>"
		if d.sparse {
			mode = ""
		}

		return envelope("<AMT_SetupAndConfigurationService><ProvisioningState>2</ProvisioningState>" +
			mode + "</AMT_SetupAndConfigurationService>"), true
	case "CIM_SoftwareIdentity.Enumerate":
		return envelope("<EnumerateResponse><EnumerationContext>ctx</EnumerationContext></EnumerateResponse>"), true
	case "CIM_SoftwareIdentity.Pull":
		items := identityItem("Flash", "16.1.25") + identityItem("AMT", "16.1.30")
		if d.sparse {
			items = identityItem("Flash", "16.1.25")
		}

		return envelope("<PullResponse><Items>" + items + "</Items></PullResponse>"), true
	case "CIM_PowerManagementService.RequestPowerStateChange":
		return envelope("<RequestPowerStateChange_OUTPUT><ReturnValue>" +
			strconv.Itoa(d.powerReturn) + "</ReturnValue></RequestPowerStateChange_OUTPUT>"), true
	default:
		return "", false
	}
}

// recorded lists the calls made, in order.
func (d *device) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.calls...)
}

func (d *device) body(call string) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.bodies[call]
}

func identityItem(instanceID, version string) string {
	return "<CIM_SoftwareIdentity><InstanceID>" + instanceID + "</InstanceID>" +
		"<VersionString>" + version + "</VersionString></CIM_SoftwareIdentity>"
}

func sourceItem(instanceID string) string {
	return "<CIM_BootSourceSetting><InstanceID>" + instanceID + "</InstanceID></CIM_BootSourceSetting>"
}

func envelope(body string) string {
	return `<?xml version="1.0" encoding="utf-8"?><Envelope><Header/><Body>` + body + `</Body></Envelope>`
}

// redirect points the library's requests at the test server; the endpoint it
// builds carries a hardcoded port.
type redirect struct{ addr string }

func (t redirect) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Host = t.addr

	return http.DefaultTransport.RoundTrip(r)
}

// bootSettings is the part of a BootSettingData Put that ForceBoot decides.
type bootSettings struct {
	InstanceID     string `xml:"Body>AMT_BootSettingData>InstanceID"`
	ElementName    string `xml:"Body>AMT_BootSettingData>ElementName"`
	BootMediaIndex int    `xml:"Body>AMT_BootSettingData>BootMediaIndex"`
	BIOSSetup      bool   `xml:"Body>AMT_BootSettingData>BIOSSetup"`
	UseIDER        bool   `xml:"Body>AMT_BootSettingData>UseIDER"`
	UseSOL         bool   `xml:"Body>AMT_BootSettingData>UseSOL"`
	LockKeyboard   bool   `xml:"Body>AMT_BootSettingData>LockKeyboard"`
}

func TestForceBoot(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	require.NoError(t, c.ForceBoot(cimboot.HardDrive, power.PowerOn))

	// The order is the invariant, and the machine must not move until both the
	// settings and the source are in place.
	assert.Equal(t, []string{
		"AMT_BootSettingData.Get",
		"AMT_BootSettingData.Put",
		"CIM_BootConfigSetting.ChangeBootOrder",
		"CIM_BootService.SetBootConfigRole",
		"CIM_PowerManagementService.RequestPowerStateChange",
	}, d.recorded())

	var got bootSettings

	require.NoError(t, xml.Unmarshal([]byte(d.body("AMT_BootSettingData.Put")), &got))

	// Reported fields are echoed back; the ones a forced boot rules out are cleared.
	assert.Equal(t, bootSettings{
		InstanceID:   "Intel(r) AMT:BootSettingData 0",
		ElementName:  "Boot Configuration",
		LockKeyboard: true,
		UseSOL:       true,
	}, got)

	assert.Contains(t, d.body("CIM_BootConfigSetting.ChangeBootOrder"), string(cimboot.HardDrive))
}

// A failed step must stop the sequence. Powering the machine on with a
// half-armed override boots whatever was configured before.
func TestForceBootStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()

	d := &device{reject: "CIM_BootConfigSetting.ChangeBootOrder"}
	c := d.serve(t)

	require.ErrorContains(t, c.ForceBoot(cimboot.PXE, power.PowerOn), "set boot source")
	assert.Equal(t, []string{
		"AMT_BootSettingData.Get",
		"AMT_BootSettingData.Put",
		"CIM_BootConfigSetting.ChangeBootOrder",
	}, d.recorded())
}

// AMT answers a refused transition with a non-zero return value and HTTP 200.
func TestChangePowerReportsARefusedTransition(t *testing.T) {
	t.Parallel()

	d := &device{powerReturn: 2}
	c := d.serve(t)

	require.ErrorContains(t, c.ChangePower(power.PowerOn), "power state change rejected")
}

func TestDevices(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	got, err := c.Devices()
	require.NoError(t, err)

	// Known sources come back as the --device values; the rest stay raw.
	assert.Equal(t, []string{"pxe", "hdd", "Intel(r) AMT: Force OCR UEFI HTTPS Boot"}, got)
	assert.Equal(t, []string{"CIM_BootSourceSetting.Enumerate", "CIM_BootSourceSetting.Pull"}, d.recorded())
}

func TestFetchInfo(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	got, err := c.FetchInfo()
	require.NoError(t, err)

	assert.Equal(t, Info{
		Power:        "On",
		Version:      "16.1.30",
		Provisioning: "Post",
		ControlMode:  "Admin",
	}, got)

	assert.Equal(t, []string{
		"CIM_AssociatedPowerManagementService.Get",
		"CIM_SoftwareIdentity.Enumerate",
		"CIM_SoftwareIdentity.Pull",
		"AMT_SetupAndConfigurationService.Get",
	}, d.recorded())
}

// An unreported field must come back empty, not the enum's zero value.
func TestFetchInfoLeavesUnreportedFieldsEmpty(t *testing.T) {
	t.Parallel()

	d := &device{sparse: true}
	c := d.serve(t)

	got, err := c.FetchInfo()
	require.NoError(t, err)

	assert.Equal(t, Info{Power: "On", Provisioning: "Post"}, got)
}

func TestFetchInfoFailsOnARefusedCall(t *testing.T) {
	t.Parallel()

	d := &device{reject: "CIM_SoftwareIdentity.Pull"}
	c := d.serve(t)

	_, err := c.FetchInfo()
	require.ErrorContains(t, err, "read software identities")
}

func TestParseDeviceRejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := ParseDevice("floppy")
	require.ErrorContains(t, err, "unknown boot device")
}
