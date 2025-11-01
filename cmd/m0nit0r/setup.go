package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/errorixlab/m0nit0r/internal/config"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure M0nit0r settings (API keys, etc.)",
	Long: `Interactive setup wizard for configuring M0nit0r.

This command will guide you through setting up:
- DeHashed API key (for breach database searches)
- OathNet API key (for breach and stealer log searches)

These API keys are stored securely in ~/.m0nit0r/config.json and are
required for credential breach scanning.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("M0nit0r Setup")
		fmt.Println("=============")
		fmt.Println()

		// Load existing config
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load existing config: %v\n", err)
			cfg = &config.Config{}
		}

		reader := bufio.NewReader(os.Stdin)

		// DeHashed API Key
		fmt.Println("DeHashed API Key")
		fmt.Println("----------------")
		fmt.Println("DeHashed provides access to billions of breached credentials.")
		fmt.Println("Get your API key at: https://www.dehashed.com/")
		if cfg.DehashedAPIKey != "" {
			fmt.Printf("Current: %s...%s (configured)\n",
				cfg.DehashedAPIKey[:min(4, len(cfg.DehashedAPIKey))],
				cfg.DehashedAPIKey[max(0, len(cfg.DehashedAPIKey)-4):])
		} else {
			fmt.Println("Current: Not configured")
		}
		fmt.Print("Enter DeHashed API key (leave blank to keep current): ")

		dehashedKey, _ := reader.ReadString('\n')
		dehashedKey = strings.TrimSpace(dehashedKey)
		if dehashedKey != "" {
			cfg.DehashedAPIKey = dehashedKey
		}

		fmt.Println()

		// OathNet API Key
		fmt.Println("OathNet API Key")
		fmt.Println("---------------")
		fmt.Println("OathNet provides access to breach databases and stealer logs.")
		fmt.Println("Get your API key at: https://oathnet.org/")
		if cfg.OathnetAPIKey != "" {
			fmt.Printf("Current: %s...%s (configured)\n",
				cfg.OathnetAPIKey[:min(4, len(cfg.OathnetAPIKey))],
				cfg.OathnetAPIKey[max(0, len(cfg.OathnetAPIKey)-4):])
		} else {
			fmt.Println("Current: Not configured")
		}
		fmt.Print("Enter OathNet API key (leave blank to keep current): ")

		oathnetKey, _ := reader.ReadString('\n')
		oathnetKey = strings.TrimSpace(oathnetKey)
		if oathnetKey != "" {
			cfg.OathnetAPIKey = oathnetKey
		}

		fmt.Println()

		// Save configuration
		if err := config.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save configuration: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Configuration saved successfully!")
		fmt.Printf("Config file: %s\n", config.GetConfigPath())
		fmt.Println()

		// Show what's configured
		fmt.Println("Configured Services:")
		if cfg.DehashedAPIKey != "" {
			fmt.Println("  [x] DeHashed")
		} else {
			fmt.Println("  [ ] DeHashed")
		}
		if cfg.OathnetAPIKey != "" {
			fmt.Println("  [x] OathNet")
		} else {
			fmt.Println("  [ ] OathNet")
		}

		fmt.Println()
		if config.HasCredentialScanningEnabled() {
			fmt.Println("Credential scanning is now enabled!")
			fmt.Println("Use: ./m0nit0r scan all --client-id <id> --type credentials")
		} else {
			fmt.Println("Note: At least one API key is required for credential scanning.")
		}
	},
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
