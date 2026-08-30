package amt

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Schema roots. Every resource below hangs off one of them.
const (
	amtSchema = "http://intel.com/wbem/wscim/1/amt-schema/1/"
	cimSchema = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
)

// The resources amtctl talks to.
const (
	bootSettingDataResource       = amtSchema + "AMT_BootSettingData"
	messageLogResource            = amtSchema + "AMT_MessageLog"
	setupAndConfigurationResource = amtSchema + "AMT_SetupAndConfigurationService"
	associatedPowerResource       = cimSchema + "CIM_AssociatedPowerManagementService"
	bootConfigSettingResource     = cimSchema + "CIM_BootConfigSetting"
	bootServiceResource           = cimSchema + "CIM_BootService"
	bootSourceSettingResource     = cimSchema + "CIM_BootSourceSetting"
	computerSystemResource        = cimSchema + "CIM_ComputerSystem"
	powerServiceResource          = cimSchema + "CIM_PowerManagementService"
	softwareIdentityResource      = cimSchema + "CIM_SoftwareIdentity"
)

const (
	addressingNS  = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	enumerationNS = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	wsmanNS       = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"

	getAction       = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
	putAction       = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
	enumerateAction = enumerationNS + "/Enumerate"
	pullAction      = enumerationNS + "/Pull"
)

const requestTimeout = 30 * time.Second

const soapContentType = "application/soap+xml; charset=utf-8"

// envelopeFormat wraps one operation. AMT answers a relative a:To and wants the
// full namespace set declared up front, so the shape stays as its own tooling
// sends it; the holes are the action, the resource and a per-request ID.
const envelopeFormat = `<?xml version="1.0" encoding="utf-8"?>` +
	`<Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
	` xmlns:xsd="http://www.w3.org/2001/XMLSchema"` +
	` xmlns:a="` + addressingNS + `"` +
	` xmlns:w="` + wsmanNS + `"` +
	` xmlns="http://www.w3.org/2003/05/soap-envelope">` +
	`<Header>` +
	`<a:Action>%s</a:Action>` +
	`<a:To>/wsman</a:To>` +
	`<w:ResourceURI>%s</w:ResourceURI>` +
	`<a:MessageID>%d</a:MessageID>` +
	`<a:ReplyTo><a:Address>` + addressingNS + `/role/anonymous</a:Address></a:ReplyTo>` +
	`<w:OperationTimeout>PT60S</w:OperationTimeout>` +
	`</Header><Body>%s</Body></Envelope>`

// post sends one SOAP operation. body and out may be nil when the operation
// takes no arguments or its result is not read.
func (c *Client) post(ctx context.Context, action, resource string, body, out any) error {
	var payload []byte

	if body != nil {
		var err error
		if payload, err = xml.Marshal(body); err != nil {
			return fmt.Errorf("build request body: %w", err)
		}
	}

	envelope := fmt.Sprintf(envelopeFormat, action, resource, c.messageID.Add(1), payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(envelope))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", soapContentType)

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post to %s: %w", c.endpoint, err)
	}

	defer res.Body.Close()

	answer, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("AMT answered %s: %s", res.Status, strings.TrimSpace(string(answer)))
	}

	if out == nil {
		return nil
	}

	if err := xml.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return nil
}

func newClient(endpoint, user, pass string) *Client {
	transport := &http.Transport{
		// AMT ships a self-signed WSMAN certificate with no CA to pin against.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
	}

	return &Client{
		endpoint: endpoint,
		http: &http.Client{
			Transport: &digest{next: transport, user: user, pass: pass},
			Timeout:   requestTimeout,
		},
	}
}

// endpointReference addresses one CIM instance, the form AMT's method
// parameters take.
type endpointReference struct {
	Address             address
	ReferenceParameters referenceParameters
}

// reference builds the endpoint reference for one instance. AMT ignores
// Address and its own tooling puts the addressing namespace there rather than
// the anonymous role URI.
func reference(resource string, selectors ...selector) endpointReference {
	return endpointReference{
		Address: address{XMLNS: addressingNS, Value: addressingNS},
		ReferenceParameters: referenceParameters{
			XMLNS:       addressingNS,
			ResourceURI: resourceURI{XMLNS: wsmanNS, Value: resource},
			SelectorSet: selectorSet{XMLNS: wsmanNS, Selectors: selectors},
		},
	}
}

func instance(id string) selector {
	return selector{Name: "InstanceID", Value: id}
}

type address struct {
	XMLName xml.Name `xml:"Address"`
	XMLNS   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

type resourceURI struct {
	XMLName xml.Name `xml:"ResourceURI"`
	XMLNS   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

type selector struct {
	XMLName xml.Name `xml:"Selector"`
	Name    string   `xml:"Name,attr"`
	Value   string   `xml:",chardata"`
}

type selectorSet struct {
	XMLName   xml.Name   `xml:"SelectorSet"`
	XMLNS     string     `xml:"xmlns,attr"`
	Selectors []selector `xml:"Selector"`
}

type referenceParameters struct {
	XMLName     xml.Name `xml:"ReferenceParameters"`
	XMLNS       string   `xml:"xmlns,attr"`
	ResourceURI resourceURI
	SelectorSet selectorSet
}

// bootSettingData is the full AMT_BootSettingData a Put has to carry. Every
// field is required: dropping the ones ForceBoot leaves at zero draws a
// SchemaValidationError rather than being read as cleared.
type bootSettingData struct {
	XMLName                 xml.Name `xml:"h:AMT_BootSettingData"`
	H                       string   `xml:"xmlns:h,attr"`
	BIOSPause               bool     `xml:"h:BIOSPause"`
	BIOSSetup               bool     `xml:"h:BIOSSetup"`
	BootMediaIndex          int      `xml:"h:BootMediaIndex"`
	ConfigurationDataReset  bool     `xml:"h:ConfigurationDataReset"`
	ElementName             string   `xml:"h:ElementName"`
	EnforceSecureBoot       bool     `xml:"h:EnforceSecureBoot"`
	FirmwareVerbosity       int      `xml:"h:FirmwareVerbosity"`
	ForcedProgressEvents    bool     `xml:"h:ForcedProgressEvents"`
	IDERBootDevice          int      `xml:"h:IDERBootDevice"`
	InstanceID              string   `xml:"h:InstanceID"`
	LockKeyboard            bool     `xml:"h:LockKeyboard"`
	LockPowerButton         bool     `xml:"h:LockPowerButton"`
	LockResetButton         bool     `xml:"h:LockResetButton"`
	LockSleepButton         bool     `xml:"h:LockSleepButton"`
	OwningEntity            string   `xml:"h:OwningEntity"`
	PlatformErase           bool     `xml:"h:PlatformErase"`
	RSEPassword             string   `xml:"h:RSEPassword"`
	ReflashBIOS             bool     `xml:"h:ReflashBIOS"`
	SecureErase             bool     `xml:"h:SecureErase"`
	UefiBootParametersArray string   `xml:"h:UefiBootParametersArray"`
	UefiBootNumberOfParams  int      `xml:"h:UefiBootNumberOfParams"`
	UseIDER                 bool     `xml:"h:UseIDER"`
	UseSOL                  bool     `xml:"h:UseSOL"`
	UseSafeMode             bool     `xml:"h:UseSafeMode"`
	UserPasswordBypass      bool     `xml:"h:UserPasswordBypass"`
}

type changeBootOrderInput struct {
	XMLName xml.Name          `xml:"h:ChangeBootOrder_INPUT"`
	H       string            `xml:"xmlns:h,attr"`
	Source  endpointReference `xml:"h:Source"`
}

type setBootConfigRoleInput struct {
	XMLName           xml.Name          `xml:"h:SetBootConfigRole_INPUT"`
	H                 string            `xml:"xmlns:h,attr"`
	BootConfigSetting endpointReference `xml:"h:BootConfigSetting"`
	Role              int               `xml:"h:Role"`
}

type requestPowerStateChangeInput struct {
	XMLName        xml.Name          `xml:"h:RequestPowerStateChange_INPUT"`
	H              string            `xml:"xmlns:h,attr"`
	PowerState     PowerState        `xml:"h:PowerState"`
	ManagedElement endpointReference `xml:"h:ManagedElement"`
}

type enumerateInput struct {
	XMLName xml.Name `xml:"Enumerate"`
	XMLNS   string   `xml:"xmlns,attr"`
}

// AMT reports a handful of boot sources, so one Pull takes them all.
const (
	pullMaxElements   = 999
	pullMaxCharacters = 99999
)

type pullInput struct {
	XMLName            xml.Name `xml:"Pull"`
	XMLNS              string   `xml:"xmlns,attr"`
	EnumerationContext string   `xml:"EnumerationContext"`
	MaxElements        int      `xml:"MaxElements"`
	MaxCharacters      int      `xml:"MaxCharacters"`
}

// pull reads the whole enumeration an Enumerate opened.
func pull(enumeration string) pullInput {
	return pullInput{
		XMLNS:              enumerationNS,
		EnumerationContext: enumeration,
		MaxElements:        pullMaxElements,
		MaxCharacters:      pullMaxCharacters,
	}
}

// maxReadRecords is the page size AMT accepts for GetRecords.
const maxReadRecords = 390

type getRecordsInput struct {
	XMLName             xml.Name `xml:"h:GetRecords_INPUT"`
	H                   string   `xml:"xmlns:h,attr"`
	IterationIdentifier int      `xml:"h:IterationIdentifier"`
	MaxReadRecords      int      `xml:"h:MaxReadRecords"`
}

// bootSettingsResponse is the part of AMT_BootSettingData that ForceBoot echoes
// back into its Put.
type bootSettingsResponse struct {
	Settings struct {
		ElementName          string `xml:"ElementName"`
		EnforceSecureBoot    bool   `xml:"EnforceSecureBoot"`
		FirmwareVerbosity    int    `xml:"FirmwareVerbosity"`
		ForcedProgressEvents bool   `xml:"ForcedProgressEvents"`
		IDERBootDevice       int    `xml:"IDERBootDevice"`
		InstanceID           string `xml:"InstanceID"`
		LockKeyboard         bool   `xml:"LockKeyboard"`
		LockPowerButton      bool   `xml:"LockPowerButton"`
		LockResetButton      bool   `xml:"LockResetButton"`
		LockSleepButton      bool   `xml:"LockSleepButton"`
		OwningEntity         string `xml:"OwningEntity"`
		UseSafeMode          bool   `xml:"UseSafeMode"`
		UserPasswordBypass   bool   `xml:"UserPasswordBypass"`
	} `xml:"Body>AMT_BootSettingData"`
}

type powerStateResponse struct {
	PowerState int `xml:"Body>CIM_AssociatedPowerManagementService>PowerState"`
}

type powerChangeResponse struct {
	ReturnValue int `xml:"Body>RequestPowerStateChange_OUTPUT>ReturnValue"`
}

type enumerateResponse struct {
	Context string `xml:"Body>EnumerateResponse>EnumerationContext"`
}

type pullResponse struct {
	InstanceIDs []string `xml:"Body>PullResponse>Items>CIM_BootSourceSetting>InstanceID"`
}

type softwareIdentityResponse struct {
	Items []struct {
		InstanceID    string `xml:"InstanceID"`
		VersionString string `xml:"VersionString"`
	} `xml:"Body>PullResponse>Items>CIM_SoftwareIdentity"`
}

type setupResponse struct {
	Service struct {
		ProvisioningMode  int `xml:"ProvisioningMode"`
		ProvisioningState int `xml:"ProvisioningState"`
	} `xml:"Body>AMT_SetupAndConfigurationService"`
}

type getRecordsResponse struct {
	Records struct {
		// RecordArray holds the base64 event records, oldest page last.
		RecordArray   []string `xml:"RecordArray"`
		NoMoreRecords bool     `xml:"NoMoreRecords"`
		ReturnValue   int      `xml:"ReturnValue"`
	} `xml:"Body>GetRecords_OUTPUT"`
}
