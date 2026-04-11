package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshcopyid"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshcopyid.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshcopyid.Run(cfg)
}
