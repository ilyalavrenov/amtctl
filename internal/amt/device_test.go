package amt

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
	// logPages are the GetRecords replies, one page per call; the read ends at
	// the last page.
	logPages [][]string
	// logReturn is the ReturnValue answered to GetRecords.
	logReturn int

	mu      sync.Mutex
	calls   []string
	bodies  map[string]string
	logPage int
}

// serve starts the device and returns a client wired to it.
func (d *device) serve(t *testing.T) *Client {
	t.Helper()

	d.bodies = make(map[string]string)

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)

	return newClient(srv.URL+"/wsman", "admin", "secret")
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
	case "AMT_MessageLog.GetRecords":
		return d.getRecords(), true
	case "CIM_PowerManagementService.RequestPowerStateChange":
		return envelope("<RequestPowerStateChange_OUTPUT><ReturnValue>" +
			strconv.Itoa(d.powerReturn) + "</ReturnValue></RequestPowerStateChange_OUTPUT>"), true
	default:
		return "", false
	}
}

// getRecords hands out one page per call, so a paged read is observable.
func (d *device) getRecords() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var page []string

	if d.logPage < len(d.logPages) {
		page = d.logPages[d.logPage]
		d.logPage++
	}

	var body strings.Builder

	body.WriteString("<GetRecords_OUTPUT>")

	for _, record := range page {
		body.WriteString("<RecordArray>" + record + "</RecordArray>")
	}

	return envelope(body.String() +
		"<NoMoreRecords>" + strconv.FormatBool(d.logPage >= len(d.logPages)) + "</NoMoreRecords>" +
		"<ReturnValue>" + strconv.Itoa(d.logReturn) + "</ReturnValue>" +
		"</GetRecords_OUTPUT>")
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

	require.NoError(t, c.ForceBoot(t.Context(), hardDrive, powerOn))

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

	assert.Contains(t, d.body("CIM_BootConfigSetting.ChangeBootOrder"), string(hardDrive))
}

// A failed step must stop the sequence. Powering the machine on with a
// half-armed override boots whatever was configured before.
func TestForceBootStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()

	d := &device{reject: "CIM_BootConfigSetting.ChangeBootOrder"}
	c := d.serve(t)

	require.ErrorContains(t, c.ForceBoot(t.Context(), pxe, powerOn), "set boot source")
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

	assert.ErrorContains(t, c.ChangePower(t.Context(), powerOn), "power state change rejected")
}

func TestDevices(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	got, err := c.Devices(t.Context())
	require.NoError(t, err)

	// Known sources come back as the --device values; the rest stay raw.
	assert.Equal(t, []string{"pxe", "hdd", "Intel(r) AMT: Force OCR UEFI HTTPS Boot"}, got)
	assert.Equal(t, []string{"CIM_BootSourceSetting.Enumerate", "CIM_BootSourceSetting.Pull"}, d.recorded())
}

func TestFetchInfo(t *testing.T) {
	t.Parallel()

	d := &device{}
	c := d.serve(t)

	got, err := c.FetchInfo(t.Context())
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

	got, err := c.FetchInfo(t.Context())
	require.NoError(t, err)

	assert.Equal(t, Info{Power: "On", Provisioning: "Post"}, got)
}

func TestFetchInfoFailsOnARefusedCall(t *testing.T) {
	t.Parallel()

	d := &device{reject: "CIM_SoftwareIdentity.Pull"}
	c := d.serve(t)

	_, err := c.FetchInfo(t.Context())
	assert.ErrorContains(t, err, "read software identities")
}

func TestPowerStateName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "On", powerStateName(2))
	assert.Equal(t, "OffSoft", powerStateName(8))
	assert.Equal(t, "unknown (99)", powerStateName(99))
}

func TestParseDeviceRejectsUnknown(t *testing.T) {
	t.Parallel()

	_, err := ParseDevice("floppy")
	assert.ErrorContains(t, err, "unknown boot device")
}

// eventRecord is the 21-byte record AMT stores per event. Only the fields the
// decoder reads are set.
type eventRecord struct {
	timestamp  uint32
	sensorType uint8
	offset     uint8
	severity   uint8
	entity     uint8
	data       []uint8
}

func (e eventRecord) encode() string {
	raw := make([]byte, 21)
	binary.LittleEndian.PutUint32(raw, e.timestamp)
	raw[5] = e.sensorType
	raw[7] = e.offset
	raw[9] = e.severity
	raw[11] = e.entity
	copy(raw[13:], e.data)

	return base64.StdEncoding.EncodeToString(raw)
}

func TestEvents(t *testing.T) {
	t.Parallel()

	d := &device{logPages: [][]string{{
		eventRecord{timestamp: 1700000000, sensorType: 6, severity: 16, entity: 38, data: []uint8{0xaa, 10, 0}}.encode(),
		eventRecord{timestamp: 1700000060, sensorType: 15, severity: 16, entity: 34, data: []uint8{0, 8}}.encode(),
		eventRecord{timestamp: 1700000120, sensorType: 18, severity: 8, entity: 33, data: []uint8{0xaa, 1, 2, 3, 4, 5, 6, 8}}.encode(),
		eventRecord{timestamp: 1700000180, sensorType: 1, severity: 16, entity: 3}.encode(),
	}}}
	c := d.serve(t)

	got, err := c.Events(t.Context())
	require.NoError(t, err)

	// The last record is a sensor type amtctl has no text for; it still has to
	// reach the caller, since severity and entity carry the diagnosis.
	assert.Equal(t, []Event{
		{
			Time:        time.Unix(1700000000, 0),
			Severity:    "Critical condition",
			Entity:      "Intel(r) ME",
			Description: "Authentication failed 10 times. The system may be under attack.",
		},
		{
			Time:        time.Unix(1700000060, 0),
			Severity:    "Critical condition",
			Entity:      "BIOS",
			Description: "Removable boot media not found.",
		},
		{
			Time:        time.Unix(1700000120, 0),
			Severity:    "Non-critical condition",
			Entity:      "System management software",
			Description: "Agent watchdog 4321-65-... changed to Expired",
		},
		{
			Time:        time.Unix(1700000180, 0),
			Severity:    "Critical condition",
			Entity:      "Processor",
			Description: "Unknown Sensor Type #1",
		},
	}, got)

	assert.Equal(t, []string{"AMT_MessageLog.GetRecords"}, d.recorded())
}

func TestEventsReadsEveryPage(t *testing.T) {
	t.Parallel()

	record := eventRecord{timestamp: 1700000000, sensorType: 30, severity: 16, entity: 34}.encode()
	d := &device{logPages: [][]string{{record, record}, {record}}}
	c := d.serve(t)

	got, err := c.Events(t.Context())
	require.NoError(t, err)

	assert.Len(t, got, 3)
	assert.Equal(t, []string{"AMT_MessageLog.GetRecords", "AMT_MessageLog.GetRecords"}, d.recorded())
	// body keeps the last call: the second read resumes past the two records the
	// first one returned.
	assert.Contains(t, d.body("AMT_MessageLog.GetRecords"), "<h:IterationIdentifier>3</h:IterationIdentifier>")
}

// AMT reports an empty log as a return value, with no record array at all.
func TestEventsReadsAnEmptyLog(t *testing.T) {
	t.Parallel()

	d := &device{logReturn: 3}
	c := d.serve(t)

	got, err := c.Events(t.Context())
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Equal(t, []string{"AMT_MessageLog.GetRecords"}, d.recorded())
}

func TestEventsReportsARefusedRead(t *testing.T) {
	t.Parallel()

	d := &device{logReturn: 1}
	c := d.serve(t)

	_, err := c.Events(t.Context())
	assert.ErrorContains(t, err, "NotSupported")
}
