package main

import (
	"os"

	"github.com/ultra-supara/sisakulint/pkg/core"
)

func main() {
	cmd := core.Command{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	os.Exit(cmd.Main(os.Args))
}
