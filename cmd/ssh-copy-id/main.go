package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/sshcopyid"
	"github.com/jamesits/sshconf/pkg/stdio"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshcopyid.Config{}
	cfg.Parse(os.Args[1:]...)
	rootLogger := logger.New("", 0, false)
	return sshcopyid.Run(cfg, stdio.NewTerminal(os.Stdin, os.Stdout, os.Stderr), rootLogger.Child("sshcopyid"))
}
