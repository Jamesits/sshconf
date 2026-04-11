package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshkeyscan"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshkeyscan.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshkeyscan.Run(cfg)
}
