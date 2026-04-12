package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshkeygen"
	"github.com/jamesits/sshconf/pkg/stdio"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshkeygen.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshkeygen.Run(cfg, stdio.NewTerminal(os.Stdin, os.Stdout, os.Stderr))
}
