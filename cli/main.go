package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
	"github.com/0xThiebaut/AdaptixC2-gopher"
)

func main() {
	cmd := cobra.Command{
		Short: "Extract the configuration from an AdaptixC2 gopher agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load the sample
			path := args[0]
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			// Attempt to brute-force it
			p, err := gopher.Bruteforce(b)
			if err != nil {
				return err
			}

			// If successful, dump it in readable JSON format
			e := json.NewEncoder(os.Stdout)
			return e.Encode(p)
		},
	}

	if err := cmd.ExecuteContext(context.Background()); err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
}
