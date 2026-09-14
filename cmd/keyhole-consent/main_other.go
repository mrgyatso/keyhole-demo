//go:build !windows

// Command keyhole-consent is the Keyhole consent window. It exists only on
// Windows; this stub keeps the repository building and testing on the
// platforms Keyhole is developed on.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "keyhole-consent: the Keyhole consent window runs on Windows only")
	os.Exit(1)
}
