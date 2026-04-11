package main

import (
	"os"

	"github.com/jamesits/sshconf/pkg/sshadd"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg := &sshadd.Config{}
	cfg.Parse(os.Args[1:]...)
	return sshadd.Run(cfg)
}
