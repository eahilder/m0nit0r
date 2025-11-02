package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/errorixlab/m0nit0r/internal/config"
	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/errorixlab/m0nit0r/internal/detector"
	"github.com/errorixlab/m0nit0r/internal/models"
	"github.com/errorixlab/m0nit0r/internal/scanner"
	"github.com/spf13/cobra"
)

var scanAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Scan all assets for a client",
	Run: func(cmd *cobra.Command, args []string) {
		clientID, _ := cmd.Flags().GetInt64("client-id")
		scanType, _ := cmd.Flags().GetString("type")
		portScanType, _ := cmd.Flags().GetString("port-type")
		verbose, _ := cmd.Flags().GetBool("verbose")

		if clientID == 0 {
			fmt.Fprintf(os.Stderr, "Error: --client-id is required\n")
			os.Exit(1)
		}

		// Get client
		client, err := database.GetClient(clientID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get client: %v\n", err)
			os.Exit(1)
		}

		// Get all assets for client
		assets, err := database.ListAssets(&clientID, nil, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list assets: %v\n", err)
			os.Exit(1)
		}

		// Check if we have assets OR if we're doing credential-only scan
		if len(assets) == 0 && scanType != "credentials" {
			fmt.Println("No assets found for this client")
			return
		}

		// If doing credential-only scan with no assets, check for primary domain
		if len(assets) == 0 && scanType == "credentials" {
			if client.PrimaryDomain == "" {
				fmt.Fprintf(os.Stderr, "No assets found and no primary domain configured for credential scanning\n")
				fmt.Fprintf(os.Stderr, "Add primary domain with: ./m0nit0r client add <name> --primary-domain <domain>\n")
				os.Exit(1)
			}
		}

		// Check baseline status per scan type
		isSubdomainBaseline := false
		isPortBaseline := false
		isCredentialBaseline := false
		isTechBaseline := false

		if scanType == "all" || scanType == "subdomains" {
			hasBaseline, err := database.HasScanTypeBaseline(clientID, "subdomains")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to check subdomain baseline status: %v\n", err)
				os.Exit(1)
			}
			isSubdomainBaseline = !hasBaseline
		}

		if scanType == "all" || scanType == "ports" {
			hasBaseline, err := database.HasScanTypeBaseline(clientID, "ports")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to check port baseline status: %v\n", err)
				os.Exit(1)
			}
			isPortBaseline = !hasBaseline
		}

		if scanType == "all" || scanType == "credentials" {
			hasBaseline, err := database.HasScanTypeBaseline(clientID, "credentials")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to check credential baseline status: %v\n", err)
				os.Exit(1)
			}
			isCredentialBaseline = !hasBaseline
		}

		if scanType == "all" || scanType == "tech" {
			hasBaseline, err := database.HasScanTypeBaseline(clientID, "tech")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to check tech baseline status: %v\n", err)
				os.Exit(1)
			}
			isTechBaseline = !hasBaseline
		}

		// Initialize summary
		// IsBaseline is true if ANY scan type is being baselined
		isAnyBaseline := isSubdomainBaseline || isPortBaseline || isCredentialBaseline || isTechBaseline

		summary := &ScanSummary{
			ClientName: client.Name,
			ClientID:   clientID,
			StartTime:  time.Now(),
			Assets:     len(assets),
			IsBaseline: isAnyBaseline,
		}

		// Count asset types
		for _, asset := range assets {
			switch asset.AssetType {
			case models.AssetTypeDomain:
				summary.Domains++
			case models.AssetTypeSubdomain:
				summary.Subdomains++
			case models.AssetTypeIP:
				summary.IPs++
			}
		}

		fmt.Printf("Scanning %d assets for client '%s'...\n\n", len(assets), client.Name)

		// Separate domains from other assets for batched subdomain scanning
		var domainAssets []models.Asset
		var otherAssets []models.Asset

		for _, asset := range assets {
			if asset.AssetType == models.AssetTypeDomain {
				domainAssets = append(domainAssets, asset)
			} else {
				otherAssets = append(otherAssets, asset)
			}
		}

		// Batched subdomain scanning for domains
		if (scanType == "all" || scanType == "subdomains") && len(domainAssets) > 0 {
			scanSubdomainsBatched(domainAssets, summary, verbose)

			// Reload assets from database to include newly discovered subdomains
			if summary.NewSubdomains > 0 {
				fmt.Printf("\nReloading assets to include %d newly discovered subdomains...\n", summary.NewSubdomains)
				reloadedAssets, err := database.ListAssets(&clientID, nil, true)
				if err == nil && len(reloadedAssets) > len(assets) {
					assets = reloadedAssets
					summary.Assets = len(assets)
					fmt.Printf("Asset list updated: now scanning %d total assets\n\n", len(assets))
				}
			}
		}

		// Scan all assets for ports and tech
		assetNum := 1
		for _, asset := range assets {
			fmt.Printf("[%d/%d] %s (%s)\n", assetNum, len(assets), asset.Value, asset.AssetType)

			// Port scan (all asset types)
			openPorts := 0
			if scanType == "all" || scanType == "ports" {
				openPorts = scanPortsForAsset(asset, portScanType, summary)
			}

			// Tech scan (domains and subdomains)
			// - If explicitly requested (scanType == "tech"), always run
			// - If part of "all" scan, only run if ports were found
			if (asset.AssetType == models.AssetTypeDomain || asset.AssetType == models.AssetTypeSubdomain) {
				if scanType == "tech" {
					// Explicit tech scan - always run
					scanTechForAsset(asset, summary)
				} else if scanType == "all" && openPorts > 0 {
					// Part of "all" scan - only run if ports are open
					scanTechForAsset(asset, summary)
				}
			}

			fmt.Println() // Blank line between assets
			assetNum++
		}

		// Credential breach scanning (if configured and requested)
		if (scanType == "all" || scanType == "credentials") && client.PrimaryDomain != "" {
			scanCredentialsForClient(client, summary)
		}

		// Calculate duration
		summary.EndTime = time.Now()
		summary.Duration = summary.EndTime.Sub(summary.StartTime)

		// Record baseline summaries for each scan type independently
		if isSubdomainBaseline && summary.SubdomainScans > 0 {
			desc := fmt.Sprintf("Baseline subdomain enumeration: %d subdomains discovered across %d domains",
				summary.TotalSubdomains, summary.SubdomainScans)
			database.RecordClientChange(clientID, "baseline_subdomain", desc, "info")

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				ClientID:    &clientID,
				ChangeType:  "baseline_subdomain",
				Description: desc,
				Severity:    "info",
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}

		if isPortBaseline && summary.PortScans > 0 {
			desc := fmt.Sprintf("Baseline port scan: %d total open ports across %d assets",
				summary.TotalOpenPorts, summary.AssetsWithOpenPorts)
			database.RecordClientChange(clientID, "baseline_portscan", desc, "info")

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				ClientID:    &clientID,
				ChangeType:  "baseline_portscan",
				Description: desc,
				Severity:    "info",
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}

		if isTechBaseline && summary.TechScansSuccess > 0 {
			desc := fmt.Sprintf("Baseline tech stack detection: %d assets scanned", summary.TechScansSuccess)
			database.RecordClientChange(clientID, "baseline_tech", desc, "info")

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				ClientID:    &clientID,
				ChangeType:  "baseline_tech",
				Description: desc,
				Severity:    "info",
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}

		if isCredentialBaseline && (summary.TotalBreachedEmails > 0 || summary.TotalBreachedPasswords > 0 || summary.TotalBreachedHashes > 0) {
			desc := fmt.Sprintf("Baseline credential breach scan: %d emails, %d passwords, %d hashes found",
				summary.TotalBreachedEmails, summary.TotalBreachedPasswords, summary.TotalBreachedHashes)
			database.RecordClientChange(clientID, "baseline_credential", desc, "info")

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				ClientID:    &clientID,
				ChangeType:  "baseline_credential",
				Description: desc,
				Severity:    "info",
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}

		// Save changes as JSON
		saveChangesJSON(client.Name, summary)

		// Display and save summary
		summaryText := generateSummaryText(summary)
		fmt.Println(summaryText)

		// Save summary to file
		saveSummary(client.Name, summaryText)
	},
}

type ScanSummary struct {
	ClientName string
	ClientID   int64
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Assets     int
	Domains    int
	Subdomains int
	IPs        int
	IsBaseline bool

	SubdomainScans       int
	NewSubdomains        int
	SubdomainChanges     int
	TotalSubdomains      int

	PortScans            int
	AssetsWithOpenPorts  int
	TotalOpenPorts       int
	NewPorts             int
	ClosedPorts          int

	TechScansSuccess     int
	TechScansFailed      int

	CredentialScans        int
	NewBreachedEmails      int
	NewBreachedPasswords   int
	TotalBreachedEmails    int
	TotalBreachedPasswords int
	TotalBreachedHashes    int

	Errors               []string
	Changes              []ChangeEvent
}

type ChangeEvent struct {
	ClientID    *int64 `json:"client_id,omitempty"`
	AssetID     *int64 `json:"asset_id,omitempty"`
	AssetValue  string `json:"asset,omitempty"`
	ChangeType  string `json:"change_type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	OldValue    string `json:"old_value,omitempty"`
	NewValue    string `json:"new_value,omitempty"`
	Timestamp   string `json:"timestamp"`
}

func scanSubdomainsBatched(domainAssets []models.Asset, summary *ScanSummary, verbose bool) {
	if len(domainAssets) == 0 {
		return
	}

	// Split into thirds (max 3 batches)
	numBatches := 3
	if len(domainAssets) < 3 {
		numBatches = len(domainAssets)
	}

	batchSize := (len(domainAssets) + numBatches - 1) / numBatches // Ceiling division
	batches := make([][]models.Asset, 0, numBatches)

	for i := 0; i < len(domainAssets); i += batchSize {
		end := i + batchSize
		if end > len(domainAssets) {
			end = len(domainAssets)
		}
		batches = append(batches, domainAssets[i:end])
	}

	fmt.Printf("Running subdomain enumeration in %d batches...\n\n", len(batches))

	// Process each batch
	for batchNum, batch := range batches {
		fmt.Printf("Batch %d/%d: Scanning %d domain(s)...\n", batchNum+1, len(batches), len(batch))

		// Extract domain values
		domains := make([]string, len(batch))
		assetMap := make(map[string]models.Asset)
		for i, asset := range batch {
			domains[i] = asset.Value
			assetMap[asset.Value] = asset
			fmt.Printf("  • %s\n", asset.Value)
		}

		// Run batch scan
		batchResult, err := scanner.EnumerateSubdomainsBatch(domains, verbose)
		if err != nil {
			for _, asset := range batch {
				summary.Errors = append(summary.Errors, fmt.Sprintf("%s - subdomain batch scan error: %v", asset.Value, err))
			}
			fmt.Printf("  ✗ Batch failed: %v\n\n", err)
			continue
		}

		if !batchResult.Success {
			for _, asset := range batch {
				summary.Errors = append(summary.Errors, fmt.Sprintf("%s - subdomain batch scan failed: %s", asset.Value, batchResult.Error))
			}
			fmt.Printf("  ✗ Batch failed: %s\n\n", batchResult.Error)
			continue
		}

		// Process results for each domain in the batch
		fmt.Printf("  ✓ Batch complete\n\n")
		for domain, result := range batchResult.Results {
			asset := assetMap[domain]
			fmt.Printf("  %s: Found %d subdomains\n", domain, result.Count)

			summary.SubdomainScans++
			summary.TotalSubdomains += result.Count

			// Check for previous scan and compare
			previous, err := database.GetLatestScanResult(asset.ID, models.ScanTypeSubdomain)

			if err != nil || previous.ID == 0 {
				// First scan - add all discovered subdomains AND record as discoveries
				for _, sub := range result.Subdomains {
					if sub == asset.Value {
						continue
					}
					database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)
					summary.NewSubdomains++

					// Record discovery (even on baseline)
					desc := fmt.Sprintf("Subdomain discovered: %s", sub)
					database.RecordChange(asset.ID, "new_subdomain", desc, "info", "", sub)

					// Track in summary for JSON output
					summary.Changes = append(summary.Changes, ChangeEvent{
						AssetID:     &asset.ID,
						AssetValue:  domain,
						ChangeType:  "new_subdomain",
						Description: desc,
						Severity:    "info",
						NewValue:    sub,
						Timestamp:   time.Now().Format(time.RFC3339),
					})
				}
			} else {
				// Compare with previous scan
				prevResult, _ := scanner.SubdomainResultFromJSON(previous.Data)
				changes := scanner.CompareSubdomains(prevResult, result)

				if changes.TotalNew > 0 {
					summary.NewSubdomains += changes.TotalNew
					summary.SubdomainChanges++
					for _, sub := range changes.NewSubdomains {
						database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)
						desc := fmt.Sprintf("New subdomain discovered: %s", sub)
						database.RecordChange(asset.ID, "new_subdomain", desc, "medium", "", sub)

						// Track in summary
						summary.Changes = append(summary.Changes, ChangeEvent{
							AssetID:     &asset.ID,
							AssetValue:  domain,
							ChangeType:  "new_subdomain",
							Description: desc,
							Severity:    "medium",
							NewValue:    sub,
							Timestamp:   time.Now().Format(time.RFC3339),
						})
					}
				}

				if changes.TotalRemoved > 0 {
					summary.SubdomainChanges++
					for _, sub := range changes.RemovedSubdomains {
						desc := fmt.Sprintf("Subdomain removed: %s", sub)
						database.RecordChange(asset.ID, "removed_subdomain", desc, "low", sub, "")

						// Track in summary
						summary.Changes = append(summary.Changes, ChangeEvent{
							AssetID:     &asset.ID,
							AssetValue:  domain,
							ChangeType:  "removed_subdomain",
							Description: desc,
							Severity:    "low",
							OldValue:    sub,
							Timestamp:   time.Now().Format(time.RFC3339),
						})
					}
				}
			}

			// Save to database
			jsonData, _ := result.ToJSON()
			database.SaveScanResult(asset.ID, models.ScanTypeSubdomain, jsonData)
		}

		fmt.Println()
	}
}

func scanSubdomainForAsset(asset models.Asset, summary *ScanSummary) {
	result, err := scanner.EnumerateSubdomains(asset.Value, false)
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s - subdomain scan error: %v", asset.Value, err))
		fmt.Printf("  → Subdomain scan: Error - %v\n", err)
		return
	}

	if !result.Success {
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s - subdomain scan failed: %s", asset.Value, result.Error))
		fmt.Printf("  → Subdomain scan: Failed - %s\n", result.Error)
		return
	}

	summary.SubdomainScans++
	fmt.Printf("  → Subdomain scan: Found %d subdomains\n", result.Count)

	// Check for previous scan and compare
	previous, err := database.GetLatestScanResult(asset.ID, models.ScanTypeSubdomain)

	if err != nil || previous.ID == 0 {
		// First scan - add all discovered subdomains
		for _, sub := range result.Subdomains {
			if sub == asset.Value {
				continue
			}
			database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)
			summary.NewSubdomains++
		}
	} else {
		// Compare with previous scan
		prevResult, _ := scanner.SubdomainResultFromJSON(previous.Data)
		changes := scanner.CompareSubdomains(prevResult, result)

		if changes.TotalNew > 0 {
			summary.NewSubdomains += changes.TotalNew
			summary.SubdomainChanges++
			for _, sub := range changes.NewSubdomains {
				database.CreateAsset(asset.ClientID, models.AssetTypeSubdomain, sub, &asset.ID)
				database.RecordChange(asset.ID, "new_subdomain",
					fmt.Sprintf("New subdomain discovered: %s", sub),
					"medium", "", sub)
			}
		}

		if changes.TotalRemoved > 0 {
			summary.SubdomainChanges++
		}
	}

	// Save to database
	jsonData, _ := result.ToJSON()
	database.SaveScanResult(asset.ID, models.ScanTypeSubdomain, jsonData)
}

func scanPortsForAsset(asset models.Asset, scanType string, summary *ScanSummary) int {
	result, err := scanner.ScanPorts(asset.Value, scanType)
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s - port scan error: %v", asset.Value, err))
		fmt.Printf("  → Port scan: Error - %v\n", err)
		return 0
	}

	summary.PortScans++

	if len(result.Ports) > 0 {
		summary.AssetsWithOpenPorts++
		summary.TotalOpenPorts += len(result.Ports)
		fmt.Printf("  → Port scan: %d ports open\n", len(result.Ports))
	} else {
		fmt.Printf("  → Port scan: Host filtered (no ports open)\n")
	}

	// Compare with previous scan
	previous, err := database.GetLatestScanResult(asset.ID, models.ScanTypePort)
	if err == nil && previous.ID != 0 {
		// Subsequent scan - record changes only
		prevResult, _ := scanner.PortScanResultFromJSON(previous.Data)
		changes := scanner.ComparePortScans(prevResult, result)

		if changes.TotalNew > 0 {
			summary.NewPorts += changes.TotalNew
			for _, port := range changes.NewPorts {
				desc := fmt.Sprintf("New port %d/%s - %s", port.Port, port.Protocol, port.Service)
				database.RecordChange(asset.ID, "new_port", desc, "medium", "", fmt.Sprintf("%d", port.Port))

				// Track in summary
				summary.Changes = append(summary.Changes, ChangeEvent{
					AssetID:     &asset.ID,
					AssetValue:  asset.Value,
					ChangeType:  "new_port",
					Description: desc,
					Severity:    "medium",
					NewValue:    fmt.Sprintf("%d", port.Port),
					Timestamp:   time.Now().Format(time.RFC3339),
				})
			}
		}

		if changes.TotalClosed > 0 {
			summary.ClosedPorts += changes.TotalClosed
			for _, port := range changes.ClosedPorts {
				desc := fmt.Sprintf("Port %d/%s closed", port.Port, port.Protocol)
				database.RecordChange(asset.ID, "closed_port", desc, "low", fmt.Sprintf("%d", port.Port), "")

				// Track in summary
				summary.Changes = append(summary.Changes, ChangeEvent{
					AssetID:     &asset.ID,
					AssetValue:  asset.Value,
					ChangeType:  "closed_port",
					Description: desc,
					Severity:    "low",
					OldValue:    fmt.Sprintf("%d", port.Port),
					Timestamp:   time.Now().Format(time.RFC3339),
				})
			}
		}
	} else {
		// First scan - record all ports as discoveries
		for _, port := range result.Ports {
			summary.NewPorts++
			desc := fmt.Sprintf("Port discovered: %d/%s - %s", port.Port, port.Protocol, port.Service)
			if port.Version != "" {
				desc += fmt.Sprintf(" [%s]", port.Version)
			}
			database.RecordChange(asset.ID, "new_port", desc, "info", "", fmt.Sprintf("%d", port.Port))

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				AssetID:     &asset.ID,
				AssetValue:  asset.Value,
				ChangeType:  "new_port",
				Description: desc,
				Severity:    "info",
				NewValue:    fmt.Sprintf("%d", port.Port),
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}
	}

	// Save to database
	jsonData, _ := result.ToJSON()
	database.SaveScanResult(asset.ID, models.ScanTypePort, jsonData)

	return len(result.Ports)
}

func scanTechForAsset(asset models.Asset, summary *ScanSummary) {
	result, err := detector.DetectTech(asset.Value)
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s - tech scan error: %v", asset.Value, err))
		summary.TechScansFailed++
		fmt.Printf("  → Tech scan: Error - %v\n", err)
		return
	}

	if !result.Success {
		summary.Errors = append(summary.Errors, fmt.Sprintf("%s - tech scan failed: %s", asset.Value, result.Error))
		summary.TechScansFailed++
		fmt.Printf("  → Tech scan: Failed - %s\n", result.Error)
		return
	}

	summary.TechScansSuccess++

	// Display key tech info
	if server, ok := result.Technologies["server"]; ok {
		fmt.Printf("  → Tech scan: %s\n", server)
	} else if webServer, ok := result.Technologies["web_server"]; ok {
		fmt.Printf("  → Tech scan: %s\n", webServer)
	} else {
		fmt.Printf("  → Tech scan: Complete\n")
	}

	// Save to database
	jsonData, _ := result.ToJSON()
	database.SaveScanResult(asset.ID, models.ScanTypeTech, jsonData)
}

func generateSummaryText(summary *ScanSummary) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("Scan Summary for '%s'\n", summary.ClientName))
	sb.WriteString("═══════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("Started:  %s\n", summary.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Finished: %s\n", summary.EndTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Duration: %s\n\n", summary.Duration.Round(time.Second)))

	sb.WriteString(fmt.Sprintf("Assets Scanned: %d ", summary.Assets))
	var types []string
	if summary.Domains > 0 {
		types = append(types, fmt.Sprintf("%d domain(s)", summary.Domains))
	}
	if summary.Subdomains > 0 {
		types = append(types, fmt.Sprintf("%d subdomain(s)", summary.Subdomains))
	}
	if summary.IPs > 0 {
		types = append(types, fmt.Sprintf("%d IP(s)", summary.IPs))
	}
	if len(types) > 0 {
		sb.WriteString(fmt.Sprintf("(%s)", strings.Join(types, ", ")))
	}
	sb.WriteString("\n\n")

	if summary.SubdomainScans > 0 {
		sb.WriteString("Subdomain Enumeration:\n")
		sb.WriteString(fmt.Sprintf("  • Scanned: %d domain(s)\n", summary.SubdomainScans))
		sb.WriteString(fmt.Sprintf("  • New subdomains discovered: %d\n", summary.NewSubdomains))
		sb.WriteString(fmt.Sprintf("  • Changes detected: %d\n\n", summary.SubdomainChanges))
	}

	if summary.PortScans > 0 {
		sb.WriteString("Port Scans:\n")
		sb.WriteString(fmt.Sprintf("  • Total scans: %d\n", summary.PortScans))
		sb.WriteString(fmt.Sprintf("  • Assets with open ports: %d\n", summary.AssetsWithOpenPorts))
		sb.WriteString(fmt.Sprintf("  • Total open ports found: %d\n", summary.TotalOpenPorts))
		if summary.NewPorts > 0 {
			sb.WriteString(fmt.Sprintf("  • New ports detected: %d\n", summary.NewPorts))
		}
		if summary.ClosedPorts > 0 {
			sb.WriteString(fmt.Sprintf("  • Closed ports: %d\n", summary.ClosedPorts))
		}
		sb.WriteString("\n")
	}

	if summary.TechScansSuccess > 0 || summary.TechScansFailed > 0 {
		sb.WriteString("Tech Detection:\n")
		sb.WriteString(fmt.Sprintf("  • Successful: %d\n", summary.TechScansSuccess))
		if summary.TechScansFailed > 0 {
			sb.WriteString(fmt.Sprintf("  • Failed: %d\n", summary.TechScansFailed))
		}
		sb.WriteString("\n")
	}

	if summary.CredentialScans > 0 {
		sb.WriteString("Credential Breach Scanning:\n")
		sb.WriteString(fmt.Sprintf("  • Total breached emails: %d\n", summary.TotalBreachedEmails))
		sb.WriteString(fmt.Sprintf("  • Total cleartext passwords: %d\n", summary.TotalBreachedPasswords))
		sb.WriteString(fmt.Sprintf("  • Total password hashes: %d\n", summary.TotalBreachedHashes))
		if summary.NewBreachedEmails > 0 {
			sb.WriteString(fmt.Sprintf("  • New breached emails: %d\n", summary.NewBreachedEmails))
		}
		if summary.NewBreachedPasswords > 0 {
			sb.WriteString(fmt.Sprintf("  • New breached passwords: %d\n", summary.NewBreachedPasswords))
		}
		sb.WriteString("\n")
	}

	if len(summary.Errors) > 0 {
		sb.WriteString(fmt.Sprintf("Errors: %d\n", len(summary.Errors)))
		for _, err := range summary.Errors {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", err))
		}
		sb.WriteString("\n")
	}

	// Output location
	home, _ := os.UserHomeDir()
	outputDir := filepath.Join(home, ".m0nit0r", "output", summary.ClientName)
	sb.WriteString(fmt.Sprintf("Output saved to: %s\n", outputDir))

	return sb.String()
}

func saveSummary(clientName, summaryText string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	outputDir := filepath.Join(home, ".m0nit0r", "output", clientName)
	os.MkdirAll(outputDir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_scan_summary.txt", timestamp)
	filepath := filepath.Join(outputDir, filename)

	os.WriteFile(filepath, []byte(summaryText), 0644)
	fmt.Printf("\nSummary saved to: %s\n", filepath)
}

func saveChangesJSON(clientName string, summary *ScanSummary) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	outputDir := filepath.Join(home, ".m0nit0r", "output", clientName)
	os.MkdirAll(outputDir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_changes.json", timestamp)
	filePath := filepath.Join(outputDir, filename)

	// Create JSON structure
	changesOutput := map[string]interface{}{
		"client":      clientName,
		"timestamp":   summary.StartTime.Format(time.RFC3339),
		"is_baseline": summary.IsBaseline,
		"summary": map[string]interface{}{
			"total_assets":         summary.Assets,
			"domains":              summary.Domains,
			"subdomains_found":     summary.TotalSubdomains,
			"ports_discovered":     summary.TotalOpenPorts,
			"new_ports":            summary.NewPorts,
			"closed_ports":         summary.ClosedPorts,
			"new_subdomains":       summary.NewSubdomains,
			"removed_subdomains":   summary.SubdomainChanges - summary.NewSubdomains,
			"total_breached_emails": summary.TotalBreachedEmails,
			"new_breached_emails":   summary.NewBreachedEmails,
		},
		"changes": summary.Changes,
	}

	jsonData, err := json.MarshalIndent(changesOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to marshal changes JSON: %v\n", err)
		return
	}

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to write changes JSON: %v\n", err)
		return
	}

	fmt.Printf("Changes saved to: %s\n", filePath)
}

func scanCredentialsForClient(client *models.Client, summary *ScanSummary) {
	// Check if credential scanning is enabled
	if !config.HasCredentialScanningEnabled() {
		fmt.Println("\nCredential Scanning: Skipped (no API keys configured)")
		fmt.Println("  Run './m0nit0r setup' to configure API keys")
		return
	}

	fmt.Println("\nCredential Breach Scanning")
	fmt.Println("==========================")
	fmt.Printf("Scanning: %s\n", client.PrimaryDomain)

	// Load config
	cfg, err := config.Get()
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("credential scan - config error: %v", err))
		fmt.Printf("  ✗ Failed to load config: %v\n", err)
		return
	}

	// Run credential scan
	result, err := scanner.ScanCredentials(client.PrimaryDomain, cfg.DehashedAPIKey, cfg.OathnetAPIKey)
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("credential scan - %s: %v", client.PrimaryDomain, err))
		fmt.Printf("  ✗ Scan failed: %v\n", err)
		return
	}

	if !result.Success {
		summary.Errors = append(summary.Errors, fmt.Sprintf("credential scan - %s: %s", client.PrimaryDomain, result.Error))
		fmt.Printf("  ✗ Scan failed: %s\n", result.Error)
		return
	}

	summary.CredentialScans++
	summary.TotalBreachedEmails = len(result.Emails)
	summary.TotalBreachedPasswords = len(result.Passwords)
	summary.TotalBreachedHashes = len(result.Hashes)

	fmt.Printf("  ✓ Found %d breached emails\n", len(result.Emails))
	fmt.Printf("  ✓ Found %d cleartext passwords\n", len(result.Passwords))
	fmt.Printf("  ✓ Found %d password hashes\n", len(result.Hashes))

	// Check for previous scan and compare
	// Note: We scan at client level, not asset level, so we need a special approach
	// We'll create a pseudo-asset ID using the client ID for storage
	pseudoAssetID := client.ID

	previous, err := database.GetLatestScanResult(pseudoAssetID, models.ScanTypeCredential)

	if err != nil || previous.ID == 0 {
		// First scan - record all as baseline discoveries
		for _, email := range result.Emails {
			desc := fmt.Sprintf("Breached email discovered: %s", email)
			database.RecordChange(pseudoAssetID, "breached_email", desc, "info", "", email)

			// Track in summary
			summary.Changes = append(summary.Changes, ChangeEvent{
				AssetID:     &pseudoAssetID,
				AssetValue:  client.PrimaryDomain,
				ChangeType:  "breached_email",
				Description: desc,
				Severity:    "info",
				NewValue:    email,
				Timestamp:   time.Now().Format(time.RFC3339),
			})
		}
	} else {
		// Compare with previous scan
		prevResult, _ := scanner.CredentialResultFromJSON(previous.Data)
		if prevResult != nil {
			changes := scanner.CompareCredentials(prevResult, result)

			if changes.TotalNew > 0 {
				summary.NewBreachedEmails = len(changes.NewEmails)
				summary.NewBreachedPasswords = len(changes.NewPasswords)

				for _, email := range changes.NewEmails {
					desc := fmt.Sprintf("New breached email discovered: %s", email)
					database.RecordChange(pseudoAssetID, "breached_email", desc, "high", "", email)

					// Track in summary
					summary.Changes = append(summary.Changes, ChangeEvent{
						AssetID:     &pseudoAssetID,
						AssetValue:  client.PrimaryDomain,
						ChangeType:  "breached_email",
						Description: desc,
						Severity:    "high",
						NewValue:    email,
						Timestamp:   time.Now().Format(time.RFC3339),
					})
				}

				for range changes.NewPasswords {
					desc := fmt.Sprintf("New breached password discovered")
					database.RecordChange(pseudoAssetID, "breached_password", desc, "high", "", "***")

					// Track in summary (don't include actual password)
					summary.Changes = append(summary.Changes, ChangeEvent{
						AssetID:     &pseudoAssetID,
						AssetValue:  client.PrimaryDomain,
						ChangeType:  "breached_password",
						Description: desc,
						Severity:    "high",
						Timestamp:   time.Now().Format(time.RFC3339),
					})
				}

				fmt.Printf("  ⚠ NEW: %d emails, %d passwords\n", len(changes.NewEmails), len(changes.NewPasswords))
			}
		}
	}

	// Save to database
	jsonData, _ := result.ToJSON()
	database.SaveScanResult(pseudoAssetID, models.ScanTypeCredential, jsonData)
}

func init() {
	scanAllCmd.Flags().Int64("client-id", 0, "Client ID to scan (required)")
	scanAllCmd.Flags().String("type", "all", "Scan type: all, ports, tech, subdomains, credentials")
	scanAllCmd.Flags().String("port-type", "quick", "Port scan type: quick or full")
	scanAllCmd.Flags().Bool("verbose", false, "Enable verbose output")
	scanAllCmd.MarkFlagRequired("client-id")

	scanCmd.AddCommand(scanAllCmd)
}
