package main

import (
	"fmt"
	"os"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "m0nit0r",
	Short: "M0nit0r - Attack Surface Management Tool",
	Long: `M0nit0r is a comprehensive CLI-based Attack Surface Management tool.

It monitors assets for changes in:
- Subdomains (via BBOT)
- Open ports
- Technology stacks
- Credential breaches

Features:
- Multi-client support
- Scheduled monitoring
- Change detection and history tracking
- JSON output for external processing`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize database for all commands except help
		if cmd.Name() != "help" && cmd.Name() != "m0nit0r" {
			if err := database.Initialize(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	// Add command groups
	rootCmd.AddCommand(clientCmd)
	rootCmd.AddCommand(assetCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(changesCmd)
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(scheduleCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(setupCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
