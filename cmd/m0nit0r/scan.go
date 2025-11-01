package main

import (
	"fmt"
	"os"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/errorixlab/m0nit0r/internal/detector"
	"github.com/errorixlab/m0nit0r/internal/models"
	"github.com/errorixlab/m0nit0r/internal/output"
	"github.com/errorixlab/m0nit0r/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run scans on assets",
}

var scanSubdomainsCmd = &cobra.Command{
	Use:   "subdomains <asset_id>",
	Short: "Enumerate subdomains for a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var assetID int64
		fmt.Sscanf(args[0], "%d", &assetID)

		verbose, _ := cmd.Flags().GetBool("verbose")

		// Get asset
		asset, err := database.GetAsset(assetID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get asset: %v\n", err)
			os.Exit(1)
		}

		if asset.AssetType != models.AssetTypeDomain {
			fmt.Fprintf(os.Stderr, "Subdomain enumeration only works on domain assets\n")
			os.Exit(1)
		}

		fmt.Printf("ℹ Enumerating subdomains for %s...\n", asset.Value)

		// Run enumeration
		result, err := scanner.EnumerateSubdomains(asset.Value, verbose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			os.Exit(1)
		}

		if !result.Success {
			fmt.Fprintf(os.Stderr, "Scan failed: %s\n", result.Error)
			os.Exit(1)
		}

		// Display results
		fmt.Printf("\nSubdomains for %s\n", asset.Value)
		fmt.Printf("Total found: %d\n\n", result.Count)

		for _, sub := range result.Subdomains {
			fmt.Printf("  • %s\n", sub)
		}

		// Check for previous scan
		previous, err := database.GetLatestScanResult(assetID, models.ScanTypeSubdomain)

		// If this is the first scan, add all discovered subdomains
		if err != nil || previous.ID == 0 {
			fmt.Printf("\n✓ Adding %d subdomains as assets...\n", result.Count)
			for _, sub := range result.Subdomains {
				// Skip the root domain itself
				if sub == asset.Value {
					continue
				}
				database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)
			}
		} else {
			// Automatically compare with previous scan
			prevResult, _ := scanner.SubdomainResultFromJSON(previous.Data)
			changes := scanner.CompareSubdomains(prevResult, result)

			if changes.TotalNew > 0 || changes.TotalRemoved > 0 {
				fmt.Printf("\n⚠ Changes Detected:\n")

				if changes.TotalNew > 0 {
					fmt.Printf("\nNew Subdomains (%d):\n", changes.TotalNew)
					for _, sub := range changes.NewSubdomains {
						fmt.Printf("  + %s\n", sub)

						// Add as asset
						database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)

						// Record change
						database.RecordChange(assetID, "new_subdomain",
							fmt.Sprintf("New subdomain discovered: %s", sub),
							"medium", "", sub)
					}
				}

				if changes.TotalRemoved > 0 {
					fmt.Printf("\nRemoved Subdomains (%d):\n", changes.TotalRemoved)
					for _, sub := range changes.RemovedSubdomains {
						fmt.Printf("  - %s\n", sub)
					}
				}
			} else {
				fmt.Println("\n✓ No changes detected")
			}
		}

		// Save to database
		jsonData, _ := result.ToJSON()
		database.SaveScanResult(assetID, models.ScanTypeSubdomain, jsonData)

		// Save output
		client, _ := database.GetClient(asset.ClientID)
		outMgr, _ := output.NewManager()
		filepath, _ := outMgr.SaveScanResult(client.Name, asset.Value, "subdomain_enum", result, false)
		fmt.Printf("\n✓ Scan saved to: %s\n", filepath)
	},
}

var scanPortsCmd = &cobra.Command{
	Use:   "ports <asset_id>",
	Short: "Scan ports on an asset",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var assetID int64
		fmt.Sscanf(args[0], "%d", &assetID)

		scanType, _ := cmd.Flags().GetString("type")

		// Get asset
		asset, err := database.GetAsset(assetID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get asset: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("ℹ Scanning %s (%s scan)...\n", asset.Value, scanType)

		// Run scan
		result, err := scanner.ScanPorts(asset.Value, scanType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			os.Exit(1)
		}

		// Display results
		fmt.Printf("\nScan Results for %s\n", asset.Value)
		fmt.Printf("State: %s\n", result.State)
		fmt.Printf("Open Ports: %d\n\n", len(result.Ports))

		if len(result.Ports) > 0 {
			for _, port := range result.Ports {
				fmt.Printf("  %d/%s  %s  %s",
					port.Port, port.Protocol, port.State, port.Service)
				if port.Version != "" {
					fmt.Printf("  [%s]", port.Version)
				}
				fmt.Printf("\n")
			}
		}

		// Automatically compare with previous scan
		previous, err := database.GetLatestScanResult(assetID, models.ScanTypePort)
		if err == nil && previous.ID != 0 {
			prevResult, _ := scanner.PortScanResultFromJSON(previous.Data)
			changes := scanner.ComparePortScans(prevResult, result)

			if changes.TotalNew > 0 || changes.TotalClosed > 0 {
				fmt.Printf("\n⚠ Changes Detected:\n")

				if changes.TotalNew > 0 {
					fmt.Printf("\nNew Ports (%d):\n", changes.TotalNew)
					for _, port := range changes.NewPorts {
						fmt.Printf("  + %d/%s - %s\n", port.Port, port.Protocol, port.Service)

						// Record change
						database.RecordChange(assetID, "new_port",
							fmt.Sprintf("New port %d/%s - %s", port.Port, port.Protocol, port.Service),
							"medium", "", fmt.Sprintf("%d", port.Port))
					}
				}

				if changes.TotalClosed > 0 {
					fmt.Printf("\nClosed Ports (%d):\n", changes.TotalClosed)
					for _, port := range changes.ClosedPorts {
						fmt.Printf("  - %d/%s - %s\n", port.Port, port.Protocol, port.Service)
					}
				}
			} else {
				fmt.Println("\n✓ No changes detected")
			}
		}

		// Save to database
		jsonData, _ := result.ToJSON()
		database.SaveScanResult(assetID, models.ScanTypePort, jsonData)

		// Save output
		client, _ := database.GetClient(asset.ClientID)
		outMgr, _ := output.NewManager()
		filepath, _ := outMgr.SaveScanResult(client.Name, asset.Value, "port_scan", result, false)
		fmt.Printf("\n✓ Scan saved to: %s\n", filepath)
	},
}

var scanTechCmd = &cobra.Command{
	Use:   "tech <asset_id>",
	Short: "Detect technology stack on a domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var assetID int64
		fmt.Sscanf(args[0], "%d", &assetID)

		// Get asset
		asset, err := database.GetAsset(assetID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get asset: %v\n", err)
			os.Exit(1)
		}

		if asset.AssetType != models.AssetTypeDomain && asset.AssetType != models.AssetTypeSubdomain {
			fmt.Fprintf(os.Stderr, "Technology scanning only works on domain/subdomain assets\n")
			os.Exit(1)
		}

		fmt.Printf("ℹ Detecting technologies for %s...\n", asset.Value)

		// Run detection
		result, err := detector.DetectTech(asset.Value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Detection failed: %v\n", err)
			os.Exit(1)
		}

		if !result.Success {
			fmt.Fprintf(os.Stderr, "Detection failed: %s\n", result.Error)
			os.Exit(1)
		}

		// Display results
		fmt.Printf("\nTechnology Stack for %s\n\n", asset.Value)
		for key, value := range result.Technologies {
			fmt.Printf("%s: %s\n", key, value)
		}

		// Automatically compare with previous scan
		previous, err := database.GetLatestScanResult(assetID, models.ScanTypeTech)
		if err == nil && previous.ID != 0 {
			prevResult, _ := detector.TechResultFromJSON(previous.Data)
			changes := detector.CompareTech(prevResult, result)

			if changes.TotalNew > 0 || changes.TotalChanged > 0 || changes.TotalRemoved > 0 {
				fmt.Printf("\n⚠ Changes Detected:\n")

				if changes.TotalNew > 0 {
					fmt.Printf("\nNew Technologies (%d):\n", changes.TotalNew)
					for _, change := range changes.NewTech {
						fmt.Printf("  + %s: %s\n", change.Category, change.NewValue)
					}
				}

				if changes.TotalChanged > 0 {
					fmt.Printf("\nChanged Technologies (%d):\n", changes.TotalChanged)
					for _, change := range changes.ChangedTech {
						fmt.Printf("  ~ %s: %s → %s\n", change.Category, change.OldValue, change.NewValue)
					}
				}
			} else {
				fmt.Println("\n✓ No changes detected")
			}
		}

		// Save to database
		jsonData, _ := result.ToJSON()
		database.SaveScanResult(assetID, models.ScanTypeTech, jsonData)

		// Save output
		client, _ := database.GetClient(asset.ClientID)
		outMgr, _ := output.NewManager()
		filepath, _ := outMgr.SaveScanResult(client.Name, asset.Value, "tech_stack", result, false)
		fmt.Printf("\n✓ Scan saved to: %s\n", filepath)
	},
}

func init() {
	scanSubdomainsCmd.Flags().BoolP("verbose", "v", false, "Show BBOT output in real-time")

	scanPortsCmd.Flags().String("type", "quick", "Scan type (quick or full)")

	scanCmd.AddCommand(scanSubdomainsCmd)
	scanCmd.AddCommand(scanPortsCmd)
	scanCmd.AddCommand(scanTechCmd)
}
