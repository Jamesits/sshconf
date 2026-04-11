package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshkeygen"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshkeygen.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshkeygen.Run(cfg)
}
