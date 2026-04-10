package gssapi

import (
	"errors"
	"fmt"
	"os"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	krb5gssapi "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Krb5Client implements [ssh.GSSAPIClient] using the pure Go gokrb5/v8 library.
// No CGO or system Kerberos libraries are required.
type Krb5Client struct {
	client *krb5client.Client

	// Context state (populated after InitSecContext)
	sessionKey  types.EncryptionKey
	established bool
}

// Krb5Config configures the Kerberos client for GSSAPI authentication.
type Krb5Config struct {
	// ConfigPath is the path to krb5.conf. If empty, tries /etc/krb5.conf.
	ConfigPath string

	// ConfigString is an alternative to ConfigPath: the krb5.conf contents
	// as a string. ConfigPath takes precedence if set.
	ConfigString string
}

// NewKrb5ClientFromCCache creates a Krb5Client from an existing credential cache.
// If ccachePath is empty, it reads the KRB5CCNAME environment variable,
// falling back to /tmp/krb5cc_<uid>.
func NewKrb5ClientFromCCache(ccachePath string, cfg Krb5Config) (*Krb5Client, error) {
	krb5Conf, err := loadKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("loading krb5 config: %w", err)
	}

	if ccachePath == "" {
		ccachePath = os.Getenv("KRB5CCNAME")
		if ccachePath == "" {
			ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
		}
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("loading credential cache %s: %w", ccachePath, err)
	}

	cl, err := krb5client.NewFromCCache(ccache, krb5Conf)
	if err != nil {
		return nil, fmt.Errorf("creating client from ccache: %w", err)
	}

	return &Krb5Client{client: cl}, nil
}

// NewKrb5ClientFromKeytab creates a Krb5Client from a keytab file.
// The client automatically performs AS exchange to obtain a TGT.
func NewKrb5ClientFromKeytab(username, realm, keytabPath string, cfg Krb5Config) (*Krb5Client, error) {
	krb5Conf, err := loadKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("loading krb5 config: %w", err)
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("loading keytab %s: %w", keytabPath, err)
	}

	cl := krb5client.NewWithKeytab(username, realm, kt, krb5Conf)
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}

	return &Krb5Client{client: cl}, nil
}

// NewKrb5ClientFromPassword creates a Krb5Client using username/password
// authentication. The client performs AS exchange to obtain a TGT.
func NewKrb5ClientFromPassword(username, realm, password string, cfg Krb5Config) (*Krb5Client, error) {
	krb5Conf, err := loadKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("loading krb5 config: %w", err)
	}

	cl := krb5client.NewWithPassword(username, realm, password, krb5Conf)
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login: %w", err)
	}

	return &Krb5Client{client: cl}, nil
}

// InitSecContext implements [ssh.GSSAPIClient]. It performs the GSSAPI/Kerberos
// token exchange for SSH authentication per RFC 4462.
//
// On the first call (token is empty), it obtains a service ticket and
// generates an AP-REQ wrapped in a GSSAPI initial context token.
//
// On subsequent calls (mutual authentication), it processes the server's
// AP-REP response.
func (c *Krb5Client) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	if c.established {
		return nil, false, errors.New("gssapi: security context already established")
	}

	if len(token) == 0 {
		// First call: generate initial context token with AP-REQ
		return c.initContext(target, isGSSDelegCreds)
	}

	// Subsequent call: process server's AP-REP for mutual auth
	return c.processReply(token)
}

func (c *Krb5Client) initContext(target string, delegCreds bool) ([]byte, bool, error) {
	// Get service ticket for the target SPN
	tkt, sessionKey, err := c.client.GetServiceTicket(target)
	if err != nil {
		return nil, false, fmt.Errorf("gssapi: obtaining service ticket for %s: %w", target, err)
	}
	c.sessionKey = sessionKey

	// Set GSSAPI context flags
	flags := []int{
		krb5gssapi.ContextFlagMutual,
		krb5gssapi.ContextFlagInteg,
	}
	if delegCreds {
		flags = append(flags, krb5gssapi.ContextFlagDeleg)
	}

	// Create KRB5 token with AP-REQ
	krb5Token, err := spnego.NewKRB5TokenAPREQ(c.client, tkt, sessionKey, flags, []int{})
	if err != nil {
		return nil, false, fmt.Errorf("gssapi: creating AP-REQ token: %w", err)
	}

	tokenBytes, err := krb5Token.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("gssapi: marshaling token: %w", err)
	}

	// needContinue=true because we expect mutual auth response
	return tokenBytes, true, nil
}

func (c *Krb5Client) processReply(token []byte) ([]byte, bool, error) {
	var krb5Token spnego.KRB5Token
	if err := krb5Token.Unmarshal(token); err != nil {
		return nil, false, fmt.Errorf("gssapi: unmarshaling server token: %w", err)
	}

	if krb5Token.IsKRBError() {
		return nil, false, fmt.Errorf("gssapi: server returned KRB-ERROR: %v", krb5Token.KRBError)
	}

	if !krb5Token.IsAPRep() {
		return nil, false, errors.New("gssapi: expected AP-REP from server")
	}

	c.established = true
	return nil, false, nil
}

// GetMIC implements [ssh.GSSAPIClient]. It generates a MIC (Message Integrity
// Code) over the SSH session ID using the Kerberos session key, per RFC 4462.
func (c *Krb5Client) GetMIC(micField []byte) ([]byte, error) {
	if c.sessionKey.KeyValue == nil {
		return nil, errors.New("gssapi: no session key (InitSecContext not completed)")
	}

	micToken, err := krb5gssapi.NewInitiatorMICToken(micField, c.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("gssapi: generating MIC token: %w", err)
	}

	tokenBytes, err := micToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("gssapi: marshaling MIC token: %w", err)
	}

	return tokenBytes, nil
}

// DeleteSecContext implements [ssh.GSSAPIClient]. It clears the security
// context state.
func (c *Krb5Client) DeleteSecContext() error {
	c.sessionKey = types.EncryptionKey{}
	c.established = false
	return nil
}

func loadKrb5Config(cfg Krb5Config) (*krb5config.Config, error) {
	if cfg.ConfigPath != "" {
		return krb5config.Load(cfg.ConfigPath)
	}
	if cfg.ConfigString != "" {
		return krb5config.NewFromString(cfg.ConfigString)
	}
	// Try default path
	return krb5config.Load("/etc/krb5.conf")
}
