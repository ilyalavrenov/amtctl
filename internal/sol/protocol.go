package sol

// The identifiers, sizes and session parameters below are fixed by the
// redirection protocol. Source of truth is the Intel AMT SDK Implementation and
// Reference Guide, "Redirection" section (reach it from the contents pane, the
// deep links redirect):
// https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/

// Redirection message identifiers.
const (
	msgStartRedirectionSession      = 0x10
	msgStartRedirectionSessionReply = 0x11
	msgAuthenticateSession          = 0x13
	msgAuthenticateSessionReply     = 0x14

	msgStartSOLRedirection      = 0x20
	msgStartSOLRedirectionReply = 0x21
	msgEndSOLRedirection        = 0x22
	msgEndSOLRedirectionReply   = 0x23
	msgSOLKeepAlivePing         = 0x24
	msgSOLDataToHost            = 0x28
	msgSOLControlsFromHost      = 0x29
	msgSOLDataFromHost          = 0x2a
	msgSOLHeartbeat             = 0x2b
)

// Fixed on-wire message sizes, header included.
const (
	lenStartRedirectionSession      = 8
	lenStartRedirectionSessionReply = 13
	lenStartSOLRedirection          = 24
	lenStartSOLRedirectionReply     = 23
	lenHeartbeat                    = 8
	lenSOLControlsFromHost          = 10
	lenEndSOLRedirectionReply       = 8
	lenSOLDataHeader                = 10
	lenAuthHeader                   = 9
)

// Authentication types offered in the AUTHENTICATE_SESSION exchange.
const (
	authQueryMethods = 0x00
	authPlain        = 0x01
	authRFC2069      = 0x03
	authRFC2617      = 0x04

	authStatusSuccess = 0x00
	authStatusFail    = 0x01
)

// The redirection digest is always computed over this URI/method pair, and the
// firmware only accepts this one nonce count.
const (
	digestURI    = "/RedirectionService"
	digestMethod = "POST"
	digestNC     = "00000002"
	cnonceBytes  = 16
)

// SOL session parameters sent in START_SOL_REDIRECTION: milliseconds except the
// buffer size.
const (
	maxTransmitBuffer       = 1000
	transmitBufferTimeout   = 100
	transmitOverflowTimeout = 0
	hostSessionRxTimeout    = 10000
	hostFIFORxFlushTimeout  = 0
	heartbeatInterval       = 5000
)

// inputBufferSize bounds one read of console input before it is framed.
const inputBufferSize = 1024

// maxAuthPayload caps the firmware-declared payload length so a hostile reply
// cannot make us allocate unbounded memory.
const maxAuthPayload = 64 << 10

// maxElementLen is the largest value a length-prefixed auth element can carry.
const maxElementLen = 255

// EscapeByte (Ctrl-]) detaches the console.
const EscapeByte = 0x1d
