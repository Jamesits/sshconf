//go:build cgo

package gssapi

/*
#cgo LDFLAGS: -lgssapi_krb5

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdlib.h>
#include <string.h>

// Helper to create a gss_buffer_desc from Go data.
static gss_buffer_desc make_buffer(void *data, size_t len) {
	gss_buffer_desc buf;
	buf.length = len;
	buf.value = data;
	return buf;
}

// initSecContext wraps gss_init_sec_context for Go.
// Returns major/minor status, output token, and whether more calls are needed.
static OM_uint32 c_init_sec_context(
	OM_uint32 *minor,
	gss_ctx_id_t *ctx,
	gss_name_t target_name,
	int deleg_creds,
	void *input_token_data, size_t input_token_len,
	void **output_token_data, size_t *output_token_len)
{
	gss_buffer_desc input_token = make_buffer(input_token_data, input_token_len);
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
	gss_OID mech = (gss_OID)gss_mech_krb5;

	OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;
	if (deleg_creds) {
		req_flags |= GSS_C_DELEG_FLAG;
	}

	OM_uint32 major = gss_init_sec_context(
		minor,
		GSS_C_NO_CREDENTIAL,   // use default credential
		ctx,
		target_name,
		mech,
		req_flags,
		0,                     // default lifetime
		GSS_C_NO_CHANNEL_BINDINGS,
		input_token_len > 0 ? &input_token : GSS_C_NO_BUFFER,
		NULL,                  // actual_mech_type
		&output_token,
		NULL,                  // ret_flags
		NULL);                 // time_rec

	*output_token_data = output_token.value;
	*output_token_len = output_token.length;
	return major;
}

// c_get_mic wraps gss_get_mic.
static OM_uint32 c_get_mic(
	OM_uint32 *minor,
	gss_ctx_id_t ctx,
	void *message_data, size_t message_len,
	void **mic_data, size_t *mic_len)
{
	gss_buffer_desc message = make_buffer(message_data, message_len);
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;

	OM_uint32 major = gss_get_mic(minor, ctx, GSS_C_QOP_DEFAULT, &message, &mic);
	*mic_data = mic.value;
	*mic_len = mic.length;
	return major;
}

// c_delete_sec_context wraps gss_delete_sec_context.
static OM_uint32 c_delete_sec_context(OM_uint32 *minor, gss_ctx_id_t *ctx) {
	return gss_delete_sec_context(minor, ctx, GSS_C_NO_BUFFER);
}

// c_import_name wraps gss_import_name for a hostbased service name.
static OM_uint32 c_import_name(
	OM_uint32 *minor,
	const char *name, size_t name_len,
	gss_name_t *output_name)
{
	gss_buffer_desc name_buf;
	name_buf.value = (void *)name;
	name_buf.length = name_len;

	return gss_import_name(minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, output_name);
}

// c_release_name wraps gss_release_name.
static OM_uint32 c_release_name(OM_uint32 *minor, gss_name_t *name) {
	return gss_release_name(minor, name);
}

// c_release_buffer wraps gss_release_buffer.
static OM_uint32 c_release_buffer(OM_uint32 *minor, gss_buffer_t buf) {
	return gss_release_buffer(minor, buf);
}

// c_display_status formats a GSSAPI status code into a string.
static void c_display_status(OM_uint32 status, int status_type, char *buf, size_t buflen) {
	OM_uint32 minor;
	OM_uint32 msg_ctx = 0;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;

	gss_display_status(&minor, status, status_type, GSS_C_NO_OID, &msg_ctx, &msg);
	size_t copy_len = msg.length;
	if (copy_len >= buflen) {
		copy_len = buflen - 1;
	}
	memcpy(buf, msg.value, copy_len);
	buf[copy_len] = '\0';
	gss_release_buffer(&minor, &msg);
}

// GSS_C_EMPTY_BUFFER is defined as a macro, so we expose it as a function.
static gss_buffer_desc empty_buffer(void) {
	gss_buffer_desc b = GSS_C_EMPTY_BUFFER;
	return b;
}

// release helper for output tokens.
static void c_free_output_token(void *data, size_t len) {
	if (data != NULL && len > 0) {
		OM_uint32 minor;
		gss_buffer_desc buf;
		buf.value = data;
		buf.length = len;
		gss_release_buffer(&minor, &buf);
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

// Verify interface compliance at compile time.
var _ ssh.GSSAPIClient = (*CGOClient)(nil)

// CGOClient implements [ssh.GSSAPIClient] using the system GSSAPI library
// (typically MIT Kerberos or Heimdal) via CGO. This requires libgssapi_krb5
// to be installed and is only available when CGO is enabled.
//
// Build with: go build (CGO_ENABLED=1 is the default)
//
// This implementation delegates all Kerberos operations to the system
// library, which handles credential caching, keytab lookup, and
// configuration via /etc/krb5.conf automatically.
type CGOClient struct {
	ctx        C.gss_ctx_id_t
	targetName C.gss_name_t
	nameSet    bool
}

// NewCGOClient creates a new CGOClient. The system GSSAPI library handles
// credential acquisition automatically from the default credential cache
// or keytab.
func NewCGOClient() *CGOClient {
	return &CGOClient{}
}

// InitSecContext implements [ssh.GSSAPIClient]. It calls the system
// gss_init_sec_context() to perform the Kerberos authentication token
// exchange.
func (c *CGOClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	// Import the target name on first call
	if !c.nameSet {
		if err := c.importName(target); err != nil {
			return nil, false, err
		}
	}

	var inputData unsafe.Pointer
	var inputLen C.size_t
	if len(token) > 0 {
		inputData = unsafe.Pointer(&token[0])
		inputLen = C.size_t(len(token))
	}

	var outputData unsafe.Pointer
	var outputLen C.size_t
	var minor C.OM_uint32

	delegFlag := C.int(0)
	if isGSSDelegCreds {
		delegFlag = 1
	}

	major := C.c_init_sec_context(
		&minor,
		&c.ctx,
		c.targetName,
		delegFlag,
		inputData, inputLen,
		&outputData, &outputLen,
	)

	if major != C.GSS_S_COMPLETE && major != C.GSS_S_CONTINUE_NEEDED {
		return nil, false, gssError("gss_init_sec_context", major, minor)
	}

	// Copy output token to Go slice and release C memory
	var out []byte
	if outputLen > 0 && outputData != nil {
		out = C.GoBytes(outputData, C.int(outputLen))
		C.c_free_output_token(outputData, outputLen)
	}

	needContinue = (major == C.GSS_S_CONTINUE_NEEDED)
	return out, needContinue, nil
}

// GetMIC implements [ssh.GSSAPIClient]. It calls gss_get_mic() to generate
// a Message Integrity Code over the SSH session ID.
func (c *CGOClient) GetMIC(micField []byte) ([]byte, error) {
	if len(micField) == 0 {
		return nil, fmt.Errorf("gssapi: empty MIC field")
	}

	var micData unsafe.Pointer
	var micLen C.size_t
	var minor C.OM_uint32

	major := C.c_get_mic(
		&minor,
		c.ctx,
		unsafe.Pointer(&micField[0]),
		C.size_t(len(micField)),
		&micData,
		&micLen,
	)

	if major != C.GSS_S_COMPLETE {
		return nil, gssError("gss_get_mic", major, minor)
	}

	mic := C.GoBytes(micData, C.int(micLen))
	C.c_free_output_token(micData, micLen)
	return mic, nil
}

// DeleteSecContext implements [ssh.GSSAPIClient]. It releases the GSSAPI
// security context and target name.
func (c *CGOClient) DeleteSecContext() error {
	var minor C.OM_uint32

	if c.ctx != nil {
		C.c_delete_sec_context(&minor, &c.ctx)
		c.ctx = nil
	}

	if c.nameSet {
		C.c_release_name(&minor, &c.targetName)
		c.nameSet = false
	}

	return nil
}

func (c *CGOClient) importName(target string) error {
	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	var minor C.OM_uint32
	major := C.c_import_name(&minor, cTarget, C.size_t(len(target)), &c.targetName)
	if major != C.GSS_S_COMPLETE {
		return gssError("gss_import_name", major, minor)
	}

	c.nameSet = true
	return nil
}

// gssError formats a GSSAPI error with major and minor status messages.
func gssError(call string, major, minor C.OM_uint32) error {
	var majorBuf [256]C.char
	var minorBuf [256]C.char

	C.c_display_status(major, C.GSS_C_GSS_CODE, &majorBuf[0], 256)
	C.c_display_status(minor, C.GSS_C_MECH_CODE, &minorBuf[0], 256)

	return fmt.Errorf("gssapi %s: %s (minor: %s)", call,
		C.GoString(&majorBuf[0]),
		C.GoString(&minorBuf[0]))
}
