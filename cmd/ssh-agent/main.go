package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshagent"
	"github.com/jamesits/sshconf/pkg/stdio"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshagent.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshagent.Run(cfg, stdio.New(os.Stdin, os.Stdout, os.Stderr))
}
