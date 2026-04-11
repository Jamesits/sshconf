package sshadd

import (
	"fmt"
	"strings"
)

// Config holds parsed ssh-add command-line arguments.
type Config struct {
	List      bool   // -l
	ListPub   bool   // -L
	Delete    bool   // -d
	DeleteAll bool   // -D
	Lock      bool   // -x
	Unlock    bool   // -X
	Confirm   bool   // -c
	Lifetime  uint32 // -t
	Files     []string
	Version   bool // -V
}

// Parse populates cfg from command-line arguments.
// Fields set before calling Parse are preserved unless overridden.
func (cfg *Config) Parse(args ...string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			cfg.List = true
		case "-L":
			cfg.ListPub = true
		case "-d":
			cfg.Delete = true
		case "-D":
			cfg.DeleteAll = true
		case "-x":
			cfg.Lock = true
		case "-X":
			cfg.Unlock = true
		case "-c":
			cfg.Confirm = true
		case "-t":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &cfg.Lifetime)
			}
		case "-V":
			cfg.Version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				cfg.Files = append(cfg.Files, args[i])
			}
		}
	}
	return nil
}
