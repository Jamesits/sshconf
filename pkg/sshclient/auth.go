package sshclient

import (
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// buildAuthMethods constructs the ordered list of ssh.AuthMethod based on
// the resolved configuration and the handlers (which carry the caller-provided
// UI).
func buildAuthMethods(opts *Options, handlers Handlers) ([]ssh.AuthMethod, error) {
	// Determine which methods are enabled
	methods := make(map[string]bool)
	methods["gssapi-with-mic"] = opts.GSSAPIAuthentication != nil && *opts.GSSAPIAuthentication
	methods["hostbased"] = opts.HostbasedAuthentication != nil && *opts.HostbasedAuthentication
	methods["publickey"] = opts.PubkeyAuthentication != nil && *opts.PubkeyAuthentication != "no"
	methods["keyboard-interactive"] = opts.KbdInteractiveAuthentication != nil && *opts.KbdInteractiveAuthentication
	methods["password"] = opts.PasswordAuthentication != nil && *opts.PasswordAuthentication

	// Parse preferred order
	order := []string{"gssapi-with-mic", "hostbased", "publickey", "keyboard-interactive", "password"}
	if opts.PreferredAuthentications != nil {
		order = splitAlgList(*opts.PreferredAuthentications)
	}

	var authMethods []ssh.AuthMethod

	for _, method := range order {
		if !methods[method] {
			continue
		}

		switch method {
		case "gssapi-with-mic":
			if handlers.GSSAPIClient == nil {
				continue
			}
			gssConfig := gssapiConfigFromOptions(opts)
			authMethods = append(authMethods,
				ssh.GSSAPIWithMICAuthMethod(&gssapiClientWrapper{
					inner:      handlers.GSSAPIClient,
					delegCreds: gssConfig.DelegateCredentials,
				}, gssConfig.Target))

		case "publickey":
			am, err := buildPublicKeyAuth(opts, handlers)
			if err != nil {
				return nil, err
			}
			if am != nil {
				authMethods = append(authMethods, am)
			}

		case "keyboard-interactive":
			if handlers.UI != nil {
				authMethods = append(authMethods, ssh.KeyboardInteractive(handlers.UI.InteractiveCallback))
			}

		case "password":
			if handlers.UI != nil {
				maxTries := 3
				if opts.NumberOfPasswordPrompts != nil {
					maxTries = *opts.NumberOfPasswordPrompts
				}
				am := ssh.PasswordCallback(handlers.UI.PasswordCallback)
				authMethods = append(authMethods, ssh.RetryableAuthMethod(am, maxTries))
			}

		case "hostbased":
			if handlers.HostbasedAuth != nil {
				am := handlers.HostbasedAuth.AuthMethod(opts)
				if am != nil {
					authMethods = append(authMethods, am)
				}
			}
		}
	}

	return authMethods, nil
}

// buildPublicKeyAuth creates a PublicKeysCallback auth method from configured
// identity files, the SSH agent, and any KeyProvider handler.
func buildPublicKeyAuth(opts *Options, handlers Handlers) (ssh.AuthMethod, error) {
	var passphraseCallback func(string) ([]byte, error)
	if handlers.UI != nil {
		passphraseCallback = handlers.UI.PassphraseCallback
	}
	return ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		var signers []ssh.Signer

		// Try SSH agent first (unless IdentitiesOnly is set)
		identitiesOnly := opts.IdentitiesOnly != nil && *opts.IdentitiesOnly
		if !identitiesOnly {
			agentSigners := getAgentSigners(opts)
			signers = append(signers, agentSigners...)
		}

		// Load keys from KeyProvider (PKCS#11, FIDO/U2F, etc.)
		if handlers.KeyProvider != nil {
			extra, err := handlers.KeyProvider.Signers(opts)
			if err == nil {
				signers = append(signers, extra...)
			}
		}

		// Load configured identity files
		for _, keyFile := range opts.IdentityFile {
			signer, err := loadPrivateKey(keyFile, passphraseCallback)
			if err != nil {
				continue // skip files that can't be loaded
			}
			if signer != nil {
				// Check for corresponding certificate
				certSigner := loadCertificate(keyFile, signer)
				if certSigner != nil {
					signers = append(signers, certSigner)
				}
				signers = append(signers, signer)
			}
		}

		// Load explicitly configured certificates
		for _, certFile := range opts.CertificateFile {
			certData, err := os.ReadFile(certFile)
			if err != nil {
				continue
			}
			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
			if err != nil {
				continue
			}
			cert, ok := pubKey.(*ssh.Certificate)
			if !ok {
				continue
			}
			// Try to find matching private key from identity files
			for _, keyFile := range opts.IdentityFile {
				signer, err := loadPrivateKey(keyFile, passphraseCallback)
				if err != nil || signer == nil {
					continue
				}
				if ssh.FingerprintSHA256(signer.PublicKey()) == ssh.FingerprintSHA256(cert.Key) {
					certSigner, err := ssh.NewCertSigner(cert, signer)
					if err == nil {
						signers = append(signers, certSigner)
					}
					break
				}
			}
		}

		return signers, nil
	}), nil
}

// getAgentSigners connects to the SSH agent and returns its signers.
func getAgentSigners(opts *Options) []ssh.Signer {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if opts.IdentityAgent != nil {
		agentPath := *opts.IdentityAgent
		switch {
		case strings.ToLower(agentPath) == "none":
			return nil
		case agentPath == "SSH_AUTH_SOCK":
			// use the default
		case strings.HasPrefix(agentPath, "$"):
			socketPath = os.Getenv(agentPath[1:])
		default:
			socketPath = agentPath
		}
	}

	if socketPath == "" {
		return nil
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil
	}

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		conn.Close()
		return nil
	}

	return signers
}

// loadPrivateKey reads and parses a private key file.
func loadPrivateKey(path string, passphraseCallback func(string) ([]byte, error)) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		// Try with passphrase if the key is encrypted
		if _, ok := err.(*ssh.PassphraseMissingError); ok && passphraseCallback != nil {
			passphrase, err := passphraseCallback(path)
			if err != nil {
				return nil, err
			}
			return ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
		}
		return nil, err
	}

	return signer, nil
}

// loadCertificate tries to load a certificate file corresponding to a private key.
// OpenSSH convention: for key "id_rsa", the cert is "id_rsa-cert.pub".
func loadCertificate(keyFile string, signer ssh.Signer) ssh.Signer {
	certFile := keyFile + "-cert.pub"
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		return nil
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil
	}

	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil
	}

	return certSigner
}
