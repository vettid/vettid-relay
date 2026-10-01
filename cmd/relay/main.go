// Command relay runs a VettID relay (see docs/RELAY-PROTOCOL.md).
package main

import (
	"fmt"
	"os"

	"github.com/vettid/vettid-relay/internal/config"
)

func main() {
	if _, err := config.FromEnv(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "relay: server not implemented yet")
	os.Exit(1)
}
