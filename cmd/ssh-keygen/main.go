package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := parseArgs(os.Args[1:])

	if args.version {
		fmt.Printf("ssh-keygen (sshconf) %s\n", version.Version)
		return 0
	}

	switch {
	case args.fingerprint:
		return cmdFingerprint(args)
	case args.changePass:
		return cmdChangePassphrase(args)
	case args.showPub:
		return cmdShowPublicKey(args)
	case args.changeComment:
		return cmdChangeComment(args)
	default:
		return cmdGenerate(args)
	}
}

type kegenArgs struct {
	keyType       string // -t
	bits          int    // -b
	comment       string // -C
	keyFile       string // -f
	newPass       string // -N
	passFile      string // -P (old passphrase for -p)
	fingerprint   bool   // -l
	changePass    bool   // -p
	changeComment bool   // -c (change comment on existing key)
	showPub       bool   // -y
	hashAlgo      string // -E (md5 or sha256)
	quiet         bool   // -q
	version       bool   // -V (not standard, but useful)
}

func parseArgs(args []string) *kegenArgs {
	a := &kegenArgs{
		keyType:  "ed25519",
		hashAlgo: "sha256",
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			i++
			if i < len(args) {
				a.keyType = args[i]
			}
		case "-b":
			i++
			if i < len(args) {
				a.bits, _ = strconv.Atoi(args[i])
			}
		case "-C":
			i++
			if i < len(args) {
				a.comment = args[i]
			}
		case "-f":
			i++
			if i < len(args) {
				a.keyFile = args[i]
			}
		case "-N":
			i++
			if i < len(args) {
				a.newPass = args[i]
			}
		case "-P":
			i++
			if i < len(args) {
				a.passFile = args[i]
			}
		case "-l":
			a.fingerprint = true
		case "-c":
			a.changeComment = true
		case "-p":
			a.changePass = true
		case "-y":
			a.showPub = true
		case "-E":
			i++
			if i < len(args) {
				a.hashAlgo = args[i]
			}
		case "-q":
			a.quiet = true
		case "-V":
			a.version = true
		case "--":
			// ignore rest
			i = len(args)
		}
	}

	return a
}

// cmdGenerate generates a new SSH key pair.
func cmdGenerate(args *kegenArgs) int {
	keyFile := args.keyFile
	if keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		switch strings.ToLower(args.keyType) {
		case "rsa":
			keyFile = filepath.Join(home, ".ssh", "id_rsa")
		case "ecdsa":
			keyFile = filepath.Join(home, ".ssh", "id_ecdsa")
		case "ed25519":
			keyFile = filepath.Join(home, ".ssh", "id_ed25519")
		default:
			keyFile = filepath.Join(home, ".ssh", "id_"+args.keyType)
		}
	}

	// Check if file exists
	if _, err := os.Stat(keyFile); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists.\n", keyFile)
		fmt.Fprintf(os.Stderr, "Overwrite (y/n)? ")
		var answer string
		fmt.Scanln(&answer)
		if !strings.HasPrefix(strings.ToLower(answer), "y") {
			return 1
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Generate key
	var privKey any
	var err error

	switch strings.ToLower(args.keyType) {
	case "rsa":
		bits := args.bits
		if bits == 0 {
			bits = 3072
		}
		if bits < 1024 {
			fmt.Fprintf(os.Stderr, "ssh-keygen: Invalid RSA key length: minimum is 1024 bits\n")
			return 1
		}
		privKey, err = rsa.GenerateKey(rand.Reader, bits)
	case "ecdsa":
		bits := args.bits
		if bits == 0 {
			bits = 256
		}
		var curve elliptic.Curve
		switch bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			fmt.Fprintf(os.Stderr, "ssh-keygen: Invalid ECDSA key length: valid lengths are 256, 384, or 521 bits\n")
			return 1
		}
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		fmt.Fprintf(os.Stderr, "ssh-keygen: unknown key type %s\n", args.keyType)
		return 1
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: key generation failed: %v\n", err)
		return 1
	}

	// Get passphrase
	passphrase := []byte(args.newPass)
	if args.newPass == "" && !args.quiet {
		fmt.Fprintf(os.Stderr, "Enter passphrase (empty for no passphrase): ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stderr, "\n")
		if err == nil && len(pw) > 0 {
			fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
			pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil || string(pw) != string(pw2) {
				fmt.Fprintf(os.Stderr, "Passphrases do not match.\n")
				return 1
			}
			passphrase = pw
		}
	}

	// Marshal private key
	var pemBlock *pem.Block
	if len(passphrase) > 0 {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, args.comment, passphrase)
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, args.comment)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Write private key
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Write public key
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}
	pubKey := signer.PublicKey()
	pubLine := string(ssh.MarshalAuthorizedKey(pubKey))
	// Trim trailing newline and append comment
	pubLine = strings.TrimSpace(pubLine)
	if args.comment != "" {
		pubLine += " " + args.comment
	}
	pubLine += "\n"

	pubFile := keyFile + ".pub"
	if err := os.WriteFile(pubFile, []byte(pubLine), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if !args.quiet {
		fmt.Fprintf(os.Stderr, "Your identification has been saved in %s\n", keyFile)
		fmt.Fprintf(os.Stderr, "Your public key has been saved in %s\n", pubFile)
		fmt.Fprintf(os.Stderr, "The key fingerprint is:\n")
		fmt.Fprintf(os.Stderr, "%s", fingerprint(pubKey, args.hashAlgo))
		if args.comment != "" {
			fmt.Fprintf(os.Stderr, " %s", args.comment)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	return 0
}

// cmdFingerprint prints the fingerprint of a key file.
func cmdFingerprint(args *kegenArgs) int {
	keyFile := args.keyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		// Try common key files
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			candidate := filepath.Join(home, ".ssh", name+".pub")
			if _, err := os.Stat(candidate); err == nil {
				keyFile = candidate
				break
			}
		}
		if keyFile == "" {
			fmt.Fprintf(os.Stderr, "ssh-keygen: No key file specified and no default key found\n")
			return 1
		}
	}

	// Try as public key first
	if !strings.HasSuffix(keyFile, ".pub") {
		if _, err := os.Stat(keyFile + ".pub"); err == nil {
			keyFile = keyFile + ".pub"
		}
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Try parsing as authorized key
	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		// Try as private key
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %s is not a key file\n", keyFile)
			return 1
		}
		pubKey = signer.PublicKey()
	}

	fp := fingerprint(pubKey, args.hashAlgo)
	size := keySize(pubKey)
	fmt.Printf("%d %s %s (%s)\n", size, fp, comment, keyTypeName(pubKey))

	return 0
}

// cmdChangePassphrase changes the passphrase on an existing private key.
func cmdChangePassphrase(args *kegenArgs) int {
	keyFile := args.keyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		keyFile = filepath.Join(home, ".ssh", "id_ed25519")
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Decrypt with old passphrase
	var privKey any
	oldPass := args.passFile

	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			if oldPass == "" {
				fmt.Fprintf(os.Stderr, "Enter old passphrase: ")
				pw, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintf(os.Stderr, "\n")
				if err != nil {
					fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
					return 1
				}
				oldPass = string(pw)
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(oldPass))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	// Get new passphrase
	newPass := args.newPass
	if newPass == "" {
		fmt.Fprintf(os.Stderr, "Enter new passphrase (empty for no passphrase): ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
		if len(pw) > 0 {
			fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
			pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil || string(pw) != string(pw2) {
				fmt.Fprintf(os.Stderr, "Passphrases do not match.\n")
				return 1
			}
		}
		newPass = string(pw)
	}

	// Re-encode
	var pemBlock *pem.Block
	if newPass != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, "", []byte(newPass))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, "")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Your identification has been saved with the new passphrase.\n")
	return 0
}

// cmdShowPublicKey extracts and prints the public key from a private key file.
func cmdShowPublicKey(args *kegenArgs) int {
	keyFile := args.keyFile
	if keyFile == "" {
		home, _ := os.UserHomeDir()
		keyFile = filepath.Join(home, ".ssh", "id_ed25519")
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	var signer ssh.Signer
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			fmt.Fprintf(os.Stderr, "Enter passphrase: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
				return 1
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, pw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return 0
}

// cmdChangeComment changes the comment on a key file.
func cmdChangeComment(args *kegenArgs) int {
	keyFile := args.keyFile
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Parse private key
	var privKey any
	privKey, err = ssh.ParseRawPrivateKey(data)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			fmt.Fprintf(os.Stderr, "Enter passphrase: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintf(os.Stderr, "\n")
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
				return 1
			}
			privKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keygen: incorrect passphrase\n")
				return 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
			return 1
		}
	}

	// Re-encode with new comment
	pemBlock, err := ssh.MarshalPrivateKey(privKey, args.comment)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-keygen: %v\n", err)
		return 1
	}

	// Update public key file
	signer, err := ssh.NewSignerFromKey(privKey)
	if err == nil {
		pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		pubLine += " " + args.comment + "\n"
		_ = os.WriteFile(keyFile+".pub", []byte(pubLine), 0644)
	}

	fmt.Fprintf(os.Stderr, "Comment '%s' applied\n", args.comment)
	return 0
}

func fingerprint(key ssh.PublicKey, algo string) string {
	switch strings.ToLower(algo) {
	case "md5":
		return ssh.FingerprintLegacyMD5(key)
	default:
		return ssh.FingerprintSHA256(key)
	}
}

func keySize(key ssh.PublicKey) int {
	cryptoKey := key.(ssh.CryptoPublicKey).CryptoPublicKey()
	switch k := cryptoKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

func keyTypeName(key ssh.PublicKey) string {
	switch key.Type() {
	case "ssh-rsa":
		return "RSA"
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return "ECDSA"
	case "ssh-ed25519":
		return "ED25519"
	default:
		return key.Type()
	}
}
