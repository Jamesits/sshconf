package main

import (
	"fmt"
	"strings"

	"github.com/jamesits/sshconf/pkg/client"
)

func runQuery(queryType string) error {
	var algs []string

	switch strings.ToLower(queryType) {
	case "cipher":
		algs = client.AllSupportedCiphers()
	case "cipher-auth":
		// AEAD ciphers that don't need a separate MAC
		for _, c := range client.AllSupportedCiphers() {
			if strings.Contains(c, "gcm") || strings.Contains(c, "chacha20") {
				algs = append(algs, c)
			}
		}
	case "mac":
		algs = client.AllSupportedMACs()
	case "kex":
		algs = client.AllSupportedKexAlgorithms()
	case "key", "hostkeytype":
		algs = client.AllSupportedHostKeyAlgorithms()
	case "key-cert":
		for _, k := range client.AllSupportedHostKeyAlgorithms() {
			if strings.Contains(k, "-cert-") {
				algs = append(algs, k)
			}
		}
	case "key-plain":
		for _, k := range client.AllSupportedHostKeyAlgorithms() {
			if !strings.Contains(k, "-cert-") {
				algs = append(algs, k)
			}
		}
	case "key-sig", "sig":
		algs = client.AllSupportedPublicKeyAlgorithms()
	case "protocol-version":
		algs = []string{"2"}
	case "compression":
		algs = []string{"none", "zlib@openssh.com"}
	default:
		return fmt.Errorf("unknown query type: %s", queryType)
	}

	for _, a := range algs {
		fmt.Println(a)
	}
	return nil
}
