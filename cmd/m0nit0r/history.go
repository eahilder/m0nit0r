package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/errorixlab/m0nit0r/internal/models"
	"github.com/errorixlab/m0nit0r/internal/scanner"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View historical scan results",
}

var historyClientCmd = &cobra.Command{
	Use:   "client",
	Short: "View scan history summaries for a client",
	Run: func(cmd *cobra.Command, args []string) {
		clientID, _ := cmd.Flags().GetInt64("client-id")
		limit, _ := cmd.Flags().GetInt("limit")
		export, _ := cmd.Flags().GetBool("export")

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

		// Get all client-level changes (baseline and scan records)
		changes, err := database.ListChanges(&clientID, nil, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get history: %v\n", err)
			os.Exit(1)
		}

		if len(changes) == 0 {
			if !export {
				fmt.Println("No scan history found")
			}
			return
		}

		// Group changes by scan date (group changes within same hour)
		type ScanSession struct {
			Timestamp       string          `json:"timestamp"`
			Type            string          `json:"type"`
			NewSubdomains   int             `json:"new_subdomains"`
			NewPorts        int             `json:"new_ports"`
			ClosedPorts     int             `json:"closed_ports"`
			Credentials     int             `json:"credentials"`
			Changes         []models.Change `json:"changes,omitempty"`

			// Baseline-specific fields
			TotalSubdomains      int `json:"total_subdomains,omitempty"`
			DomainsScanned       int `json:"domains_scanned,omitempty"`
			TotalOpenPorts       int `json:"total_open_ports,omitempty"`
			AssetsWithOpenPorts  int `json:"assets_with_open_ports,omitempty"`
			TechScansSuccess     int `json:"tech_scans_success,omitempty"`
			TotalBreachedEmails  int `json:"total_breached_emails,omitempty"`
			TotalBreachedPwds    int `json:"total_breached_passwords,omitempty"`
			TotalBreachedHashes  int `json:"total_breached_hashes,omitempty"`
		}

		var sessions []ScanSession
		var currentSession *ScanSession

		for _, change := range changes {
			timestamp := change.CreatedAt.Format("2006-01-02 15:04")

			if currentSession == nil || currentSession.Timestamp != timestamp {
				if currentSession != nil {
					sessions = append(sessions, *currentSession)
				}
				currentSession = &ScanSession{
					Timestamp: timestamp,
					Changes:   []models.Change{change},
				}
			} else {
				currentSession.Changes = append(currentSession.Changes, change)
			}
		}
		if currentSession != nil {
			sessions = append(sessions, *currentSession)
		}

		// Apply limit
		if limit > 0 && len(sessions) > limit {
			sessions = sessions[:limit]
		}

		// Process sessions to count change types
		for i := range sessions {
			baseline := 0
			for _, change := range sessions[i].Changes {
				if strings.HasPrefix(change.ChangeType, "baseline_") {
					baseline++
					// Parse baseline description to extract detailed metrics
					metrics := parseBaselineDescription(change.ChangeType, change.Description)
					for key, value := range metrics {
						switch key {
						case "total_subdomains":
							sessions[i].TotalSubdomains = value
						case "domains_scanned":
							sessions[i].DomainsScanned = value
						case "total_open_ports":
							sessions[i].TotalOpenPorts = value
						case "assets_with_open_ports":
							sessions[i].AssetsWithOpenPorts = value
						case "tech_scans_success":
							sessions[i].TechScansSuccess = value
						case "total_breached_emails":
							sessions[i].TotalBreachedEmails = value
						case "total_breached_passwords":
							sessions[i].TotalBreachedPwds = value
						case "total_breached_hashes":
							sessions[i].TotalBreachedHashes = value
						}
					}
				} else if change.ChangeType == "new_subdomain" {
					sessions[i].NewSubdomains++
				} else if change.ChangeType == "new_port" {
					sessions[i].NewPorts++
				} else if change.ChangeType == "closed_port" {
					sessions[i].ClosedPorts++
				} else if change.ChangeType == "breached_email" {
					sessions[i].Credentials++
				}
			}

			if baseline > 0 {
				sessions[i].Type = "Baseline Scan"
			} else {
				sessions[i].Type = "Delta Scan"
			}
		}

		// Export as JSON or display
		if export {
			output := map[string]interface{}{
				"client":       client.Name,
				"total_scans":  len(sessions),
				"scan_history": sessions,
			}
			jsonData, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(jsonData))
			return
		}

		// Display formatted output
		fmt.Printf("Scan History for Client: %s\n", client.Name)
		fmt.Println(strings.Repeat("═", 70))
		fmt.Println()

		for i, session := range sessions {
			fmt.Printf("[%d] Scan: %s\n", i+1, session.Timestamp)
			fmt.Printf("    Type: %s\n", session.Type)
			fmt.Println()

			if session.Type == "Baseline Scan" {
				// Display baseline details similar to scan summary
				if session.TotalSubdomains > 0 || session.DomainsScanned > 0 {
					fmt.Println("    Subdomain Enumeration:")
					if session.DomainsScanned > 0 {
						fmt.Printf("      • Domains scanned: %d\n", session.DomainsScanned)
					}
					if session.TotalSubdomains > 0 {
						fmt.Printf("      • Total subdomains discovered: %d\n", session.TotalSubdomains)
					}
					fmt.Println()
				}

				if session.TotalOpenPorts > 0 || session.AssetsWithOpenPorts > 0 {
					fmt.Println("    Port Scanning:")
					if session.AssetsWithOpenPorts > 0 {
						fmt.Printf("      • Assets with open ports: %d\n", session.AssetsWithOpenPorts)
					}
					if session.TotalOpenPorts > 0 {
						fmt.Printf("      • Total open ports found: %d\n", session.TotalOpenPorts)
					}
					fmt.Println()
				}

				if session.TechScansSuccess > 0 {
					fmt.Println("    Tech Detection:")
					fmt.Printf("      • Assets scanned: %d\n", session.TechScansSuccess)
					fmt.Println()
				}

				if session.TotalBreachedEmails > 0 || session.TotalBreachedPwds > 0 || session.TotalBreachedHashes > 0 {
					fmt.Println("    Credential Breach Scanning:")
					if session.TotalBreachedEmails > 0 {
						fmt.Printf("      • Breached emails: %d\n", session.TotalBreachedEmails)
					}
					if session.TotalBreachedPwds > 0 {
						fmt.Printf("      • Cleartext passwords: %d\n", session.TotalBreachedPwds)
					}
					if session.TotalBreachedHashes > 0 {
						fmt.Printf("      • Password hashes: %d\n", session.TotalBreachedHashes)
					}
					fmt.Println()
				}
			} else {
				// Display delta scan changes
				if session.NewSubdomains > 0 {
					fmt.Printf("    ✓ New subdomains: %d\n", session.NewSubdomains)
				}
				if session.NewPorts > 0 {
					fmt.Printf("    ✓ New ports: %d\n", session.NewPorts)
				}
				if session.ClosedPorts > 0 {
					fmt.Printf("    ✗ Closed ports: %d\n", session.ClosedPorts)
				}
				if session.Credentials > 0 {
					fmt.Printf("    ⚠ Credentials: %d\n", session.Credentials)
				}
				if session.NewSubdomains == 0 && session.NewPorts == 0 && session.ClosedPorts == 0 {
					fmt.Println("    - No changes detected")
				}
				fmt.Println()
			}

			if i < len(sessions)-1 {
				fmt.Println(strings.Repeat("-", 70))
				fmt.Println()
			}
		}

		fmt.Println()
		fmt.Printf("Total scans: %d\n", len(sessions))
	},
}

var historyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List historical scan results for an asset",
	Run: func(cmd *cobra.Command, args []string) {
		assetID, _ := cmd.Flags().GetInt64("asset-id")
		scanType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")
		export, _ := cmd.Flags().GetBool("export")

		if assetID == 0 {
			fmt.Fprintf(os.Stderr, "Error: --asset-id is required\n")
			os.Exit(1)
		}

		// Get asset details
		assets, err := database.ListAssets(nil, nil, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get asset: %v\n", err)
			os.Exit(1)
		}

		var asset *models.Asset
		for _, a := range assets {
			if a.ID == assetID {
				asset = &a
				break
			}
		}

		if asset == nil {
			fmt.Fprintf(os.Stderr, "Asset not found: %d\n", assetID)
			os.Exit(1)
		}

		// Get all scan results for this asset
		var results []models.ScanResult
		query := database.DB.Where("asset_id = ?", assetID).Order("created_at DESC")

		if scanType != "" {
			query = query.Where("scan_type = ?", scanType)
		}

		if limit > 0 {
			query = query.Limit(limit)
		}

		if err := query.Find(&results).Error; err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get scan results: %v\n", err)
			os.Exit(1)
		}

		if len(results) == 0 {
			if !export {
				fmt.Println("No scan history found")
			}
			return
		}

		// Export as JSON or display
		if export {
			output := map[string]interface{}{
				"asset":        asset.Value,
				"asset_type":   asset.AssetType,
				"total_scans":  len(results),
				"scan_results": results,
			}
			jsonData, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(jsonData))
			return
		}

		// Display formatted output
		fmt.Printf("Scan History for: %s (%s)\n", asset.Value, asset.AssetType)
		fmt.Println(strings.Repeat("═", 60))
		fmt.Println()

		for i, result := range results {
			fmt.Printf("[%d] %s - %s\n", i+1, result.ScanType, result.CreatedAt.Format("2006-01-02 15:04:05"))

			// Parse and display relevant data based on scan type
			switch result.ScanType {
			case models.ScanTypePort:
				displayPortScanResult(result.Data)
			case models.ScanTypeSubdomain:
				displaySubdomainResult(result.Data)
			case models.ScanTypeTech:
				displayTechResult(result.Data)
			case models.ScanTypeCredential:
				displayCredentialResult(result.Data)
			}

			if i < len(results)-1 {
				fmt.Println()
			}
		}
	},
}

var historyCompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two scan results",
	Run: func(cmd *cobra.Command, args []string) {
		assetID, _ := cmd.Flags().GetInt64("asset-id")
		scanType, _ := cmd.Flags().GetString("type")
		export, _ := cmd.Flags().GetBool("export")

		if assetID == 0 {
			fmt.Fprintf(os.Stderr, "Error: --asset-id is required\n")
			os.Exit(1)
		}

		if scanType == "" {
			fmt.Fprintf(os.Stderr, "Error: --type is required (port, subdomain, tech, credential)\n")
			os.Exit(1)
		}

		// Get last two scan results
		var results []models.ScanResult
		if err := database.DB.Where("asset_id = ? AND scan_type = ?", assetID, scanType).
			Order("created_at DESC").Limit(2).Find(&results).Error; err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get scan results: %v\n", err)
			os.Exit(1)
		}

		if len(results) < 2 {
			if !export {
				fmt.Println("Not enough scan history to compare (need at least 2 scans)")
			}
			return
		}

		// Get asset details
		assets, _ := database.ListAssets(nil, nil, false)
		var asset *models.Asset
		for _, a := range assets {
			if a.ID == assetID {
				asset = &a
				break
			}
		}

		if asset == nil {
			fmt.Fprintf(os.Stderr, "Asset not found: %d\n", assetID)
			os.Exit(1)
		}

		// Export as JSON or display
		if export {
			var comparison interface{}

			// Get comparison data based on scan type
			switch models.ScanType(scanType) {
			case models.ScanTypePort:
				oldResult, _ := scanner.PortScanResultFromJSON(results[1].Data)
				newResult, _ := scanner.PortScanResultFromJSON(results[0].Data)
				comparison = scanner.ComparePortScans(oldResult, newResult)
			case models.ScanTypeSubdomain:
				oldResult, _ := scanner.SubdomainResultFromJSON(results[1].Data)
				newResult, _ := scanner.SubdomainResultFromJSON(results[0].Data)
				comparison = scanner.CompareSubdomains(oldResult, newResult)
			default:
				comparison = map[string]string{"error": "Comparison not available for this scan type"}
			}

			output := map[string]interface{}{
				"asset":            asset.Value,
				"scan_type":        scanType,
				"previous_scan":    results[1].CreatedAt.Format("2006-01-02 15:04:05"),
				"current_scan":     results[0].CreatedAt.Format("2006-01-02 15:04:05"),
				"comparison":       comparison,
			}

			jsonData, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(jsonData))
			return
		}

		// Display formatted output
		fmt.Printf("Comparing Scans for: %s\n", asset.Value)
		fmt.Println(strings.Repeat("═", 60))
		fmt.Printf("Previous: %s\n", results[1].CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Current:  %s\n", results[0].CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()

		// Compare based on scan type
		switch models.ScanType(scanType) {
		case models.ScanTypePort:
			comparePortScans(results[1].Data, results[0].Data)
		case models.ScanTypeSubdomain:
			compareSubdomainScans(results[1].Data, results[0].Data)
		default:
			fmt.Println("Comparison not available for this scan type")
		}
	},
}

func displayPortScanResult(data string) {
	result, err := scanner.PortScanResultFromJSON(data)
	if err != nil {
		fmt.Printf("    Error parsing data: %v\n", err)
		return
	}

	if len(result.Ports) == 0 {
		fmt.Println("    No open ports")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "    PORT\tSTATE\tSERVICE\tVERSION")
	for _, port := range result.Ports {
		version := port.Version
		if version == "" {
			version = "-"
		}
		fmt.Fprintf(w, "    %d/%s\t%s\t%s\t%s\n",
			port.Port, port.Protocol, port.State, port.Service, version)
	}
	w.Flush()
}

func displaySubdomainResult(data string) {
	result, err := scanner.SubdomainResultFromJSON(data)
	if err != nil {
		fmt.Printf("    Error parsing data: %v\n", err)
		return
	}

	fmt.Printf("    Found %d subdomains\n", result.Count)
	if result.Count > 0 && result.Count <= 10 {
		for _, sub := range result.Subdomains {
			fmt.Printf("      - %s\n", sub)
		}
	} else if result.Count > 10 {
		fmt.Println("    (too many to display, showing first 10)")
		for i := 0; i < 10 && i < len(result.Subdomains); i++ {
			fmt.Printf("      - %s\n", result.Subdomains[i])
		}
	}
}

func displayTechResult(data string) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		fmt.Printf("    Error parsing data: %v\n", err)
		return
	}

	if techs, ok := result["technologies"].([]interface{}); ok && len(techs) > 0 {
		fmt.Printf("    Found %d technologies\n", len(techs))
		for _, tech := range techs {
			if t, ok := tech.(map[string]interface{}); ok {
				name := t["name"]
				version := t["version"]
				if version != nil && version != "" {
					fmt.Printf("      - %s (%v)\n", name, version)
				} else {
					fmt.Printf("      - %s\n", name)
				}
			}
		}
	} else {
		fmt.Println("    No technologies detected")
	}
}

func displayCredentialResult(data string) {
	result, err := scanner.CredentialResultFromJSON(data)
	if err != nil {
		fmt.Printf("    Error parsing data: %v\n", err)
		return
	}

	fmt.Printf("    Breached emails: %d\n", len(result.Emails))
	fmt.Printf("    Cleartext passwords: %d\n", len(result.Passwords))
	fmt.Printf("    Password hashes: %d\n", len(result.Hashes))
}

func comparePortScans(oldData, newData string) {
	oldResult, err1 := scanner.PortScanResultFromJSON(oldData)
	newResult, err2 := scanner.PortScanResultFromJSON(newData)

	if err1 != nil || err2 != nil {
		fmt.Println("Error parsing scan data")
		return
	}

	changes := scanner.ComparePortScans(oldResult, newResult)

	if changes.TotalNew == 0 && changes.TotalClosed == 0 {
		fmt.Println("✓ No changes detected")
		return
	}

	if changes.TotalNew > 0 {
		fmt.Printf("\n✓ New Ports (%d):\n", changes.TotalNew)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, port := range changes.NewPorts {
			fmt.Fprintf(w, "  + %d/%s\t%s\t%s\n",
				port.Port, port.Protocol, port.Service, port.Version)
		}
		w.Flush()
	}

	if changes.TotalClosed > 0 {
		fmt.Printf("\n✗ Closed Ports (%d):\n", changes.TotalClosed)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, port := range changes.ClosedPorts {
			fmt.Fprintf(w, "  - %d/%s\t%s\n",
				port.Port, port.Protocol, port.Service)
		}
		w.Flush()
	}
}

func compareSubdomainScans(oldData, newData string) {
	oldResult, err1 := scanner.SubdomainResultFromJSON(oldData)
	newResult, err2 := scanner.SubdomainResultFromJSON(newData)

	if err1 != nil || err2 != nil {
		fmt.Println("Error parsing scan data")
		return
	}

	changes := scanner.CompareSubdomains(oldResult, newResult)

	if changes.TotalNew == 0 && changes.TotalRemoved == 0 {
		fmt.Println("✓ No changes detected")
		return
	}

	if changes.TotalNew > 0 {
		fmt.Printf("\n✓ New Subdomains (%d):\n", changes.TotalNew)
		for _, sub := range changes.NewSubdomains {
			fmt.Printf("  + %s\n", sub)
		}
	}

	if changes.TotalRemoved > 0 {
		fmt.Printf("\n✗ Removed Subdomains (%d):\n", changes.TotalRemoved)
		for _, sub := range changes.RemovedSubdomains {
			fmt.Printf("  - %s\n", sub)
		}
	}
}

// parseBaselineDescription extracts metrics from baseline change descriptions
func parseBaselineDescription(changeType, description string) map[string]int {
	metrics := make(map[string]int)

	// Extract numbers from description using regex
	re := regexp.MustCompile(`\d+`)
	numbers := re.FindAllString(description, -1)

	switch changeType {
	case "baseline_subdomain":
		// "Baseline subdomain enumeration: X subdomains discovered across Y domains"
		if len(numbers) >= 2 {
			if total, err := strconv.Atoi(numbers[0]); err == nil {
				metrics["total_subdomains"] = total
			}
			if domains, err := strconv.Atoi(numbers[1]); err == nil {
				metrics["domains_scanned"] = domains
			}
		}
	case "baseline_portscan":
		// "Baseline port scan: X total open ports across Y assets"
		if len(numbers) >= 2 {
			if ports, err := strconv.Atoi(numbers[0]); err == nil {
				metrics["total_open_ports"] = ports
			}
			if assets, err := strconv.Atoi(numbers[1]); err == nil {
				metrics["assets_with_open_ports"] = assets
			}
		}
	case "baseline_tech":
		// "Baseline tech stack detection: X assets scanned"
		if len(numbers) >= 1 {
			if scans, err := strconv.Atoi(numbers[0]); err == nil {
				metrics["tech_scans_success"] = scans
			}
		}
	case "baseline_credential":
		// "Baseline credential breach scan: X emails, Y passwords, Z hashes found"
		if len(numbers) >= 3 {
			if emails, err := strconv.Atoi(numbers[0]); err == nil {
				metrics["total_breached_emails"] = emails
			}
			if pwds, err := strconv.Atoi(numbers[1]); err == nil {
				metrics["total_breached_passwords"] = pwds
			}
			if hashes, err := strconv.Atoi(numbers[2]); err == nil {
				metrics["total_breached_hashes"] = hashes
			}
		}
	}

	return metrics
}

func init() {
	historyClientCmd.Flags().Int64("client-id", 0, "Client ID to view history for")
	historyClientCmd.Flags().Int("limit", 10, "Limit number of scan sessions to show")
	historyClientCmd.Flags().Bool("export", false, "Export history as JSON")

	historyListCmd.Flags().Int64("asset-id", 0, "Asset ID to view history for")
	historyListCmd.Flags().String("type", "", "Filter by scan type (port, subdomain, tech, credential)")
	historyListCmd.Flags().Int("limit", 10, "Limit number of results")
	historyListCmd.Flags().Bool("export", false, "Export scan results as JSON")

	historyCompareCmd.Flags().Int64("asset-id", 0, "Asset ID to compare scans for")
	historyCompareCmd.Flags().String("type", "", "Scan type to compare (port, subdomain)")
	historyCompareCmd.Flags().Bool("export", false, "Export comparison as JSON")

	historyCmd.AddCommand(historyClientCmd)
	historyCmd.AddCommand(historyListCmd)
	historyCmd.AddCommand(historyCompareCmd)
}
