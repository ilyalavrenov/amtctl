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

// bootSettings is the part of a BootSettingData Put that ForcePXE decides.
type bootSettings struct {
	InstanceID     string `xml:"Body>AMT_BootSettingData>InstanceID"`
	ElementName    string `xml:"Body>AMT_BootSettingData>ElementName"`
	BootMediaIndex int    `xml:"Body>AMT_BootSettingData>BootMediaIndex"`
	BIOSSetup      bool   `xml:"Body>AMT_BootSettingData>BIOSSetup"`
	UseIDER        bool   `xml:"Body>AMT_BootSettingData>UseIDER"`
	UseSOL         bool   `xml:"Body>AMT_BootSettingData>UseSOL"`
	LockKeyboard   bool   `xml:"Body>AMT_BootSettingData>LockKeyboard"`
}

func TestForcePXE(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	require.NoError(t, c.ForcePXE(power.PowerOn))

	// The order is the invariant: settings are consulted only once a source is
	// set, the source takes effect only once promoted to next boot, and the
	// machine must not move until both are done.
	assert.Equal(t, []string{
		"AMT_BootSettingData.Get",
		"AMT_BootSettingData.Put",
		"CIM_BootConfigSetting.ChangeBootOrder",
		"CIM_BootService.SetBootConfigRole",
		"CIM_PowerManagementService.RequestPowerStateChange",
	}, d.recorded())

	var got bootSettings

	require.NoError(t, xml.Unmarshal([]byte(d.body("AMT_BootSettingData.Put")), &got))

	// Reported fields are echoed back; the ones a PXE boot rules out are cleared.
	assert.Equal(t, bootSettings{
		InstanceID:   "Intel(r) AMT:BootSettingData 0",
		ElementName:  "Boot Configuration",
		LockKeyboard: true,
		UseSOL:       true,
	}, got)
}

// A failed step must stop the sequence. Powering the machine on with a
// half-armed override boots whatever was configured before.
func TestForcePXEStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()

	d := &device{reject: "CIM_BootConfigSetting.ChangeBootOrder"}
	c := d.serve(t)

	require.ErrorContains(t, c.ForcePXE(power.PowerOn), "set PXE boot source")
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
