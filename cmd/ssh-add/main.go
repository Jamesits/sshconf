package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshadd"
	"github.com/jamesits/sshconf/pkg/stdio"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshadd.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshadd.Run(cfg, stdio.NewTerminal(os.Stdin, os.Stdout, os.Stderr))
}
