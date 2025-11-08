package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/errorixlab/m0nit0r/internal/models"
	"github.com/spf13/cobra"
)

var assetCmd = &cobra.Command{
	Use:   "asset",
	Short: "Manage assets (domains, IPs, etc.)",
}

var assetAddCmd = &cobra.Command{
	Use:   "add <client_id> <type> <value>",
	Short: "Add a new asset",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		var clientID int64
		fmt.Sscanf(args[0], "%d", &clientID)

		assetType := models.AssetType(args[1])
		value := args[2]

		// Validate asset type
		if assetType != models.AssetTypeDomain &&
		   assetType != models.AssetTypeSubdomain &&
		   assetType != models.AssetTypeIP {
			fmt.Fprintf(os.Stderr, "Invalid asset type. Must be: domain, subdomain, or ip\n")
			os.Exit(1)
		}

		asset, err := database.CreateAsset(clientID, assetType, value, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create asset: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Created %s: %s (ID: %d)\n", asset.AssetType, asset.Value, asset.ID)
	},
}

var assetListCmd = &cobra.Command{
	Use:   "list",
	Short: "List assets",
	Run: func(cmd *cobra.Command, args []string) {
		var clientID *int64
		clientIDFlag, _ := cmd.Flags().GetInt64("client-id")
		if clientIDFlag > 0 {
			clientID = &clientIDFlag
		}

		var assetType *models.AssetType
		assetTypeFlag, _ := cmd.Flags().GetString("type")
		if assetTypeFlag != "" {
			at := models.AssetType(assetTypeFlag)
			assetType = &at
		}

		activeOnly, _ := cmd.Flags().GetBool("active-only")
		export, _ := cmd.Flags().GetBool("export")

		assets, err := database.ListAssets(clientID, assetType, activeOnly)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list assets: %v\n", err)
			os.Exit(1)
		}

		if len(assets) == 0 {
			if !export {
				fmt.Println("No assets found")
			}
			return
		}

		// Export as JSON or display
		if export {
			// Get client name if filtering by client
			clientName := ""
			if clientID != nil {
				client, err := database.GetClient(*clientID)
				if err == nil {
					clientName = client.Name
				}
			}

			// Count assets by type
			counts := make(map[models.AssetType]int)
			for _, asset := range assets {
				counts[asset.AssetType]++
			}

			output := map[string]interface{}{
				"total_assets": len(assets),
				"counts": map[string]interface{}{
					"domains":    counts[models.AssetTypeDomain],
					"subdomains": counts[models.AssetTypeSubdomain],
					"ips":        counts[models.AssetTypeIP],
				},
				"assets": assets,
			}

			if clientName != "" {
				output["client"] = clientName
			}
			if assetTypeFlag != "" {
				output["filtered_by_type"] = assetTypeFlag
			}
			if activeOnly {
				output["active_only"] = true
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
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTYPE\tVALUE\tACTIVE\tCREATED")
		fmt.Fprintln(w, "--\t----\t-----\t------\t-------")

		for _, asset := range assets {
			active := "✓"
			if !asset.Active {
				active = "✗"
			}

			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
				asset.ID,
				asset.AssetType,
				asset.Value,
				active,
				asset.CreatedAt.Format("2006-01-02 15:04"),
			)
		}

		w.Flush()
	},
}

var assetImportCmd = &cobra.Command{
	Use:   "import <client_id> <file>",
	Short: "Import assets from a file (one per line)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		var clientID int64
		fmt.Sscanf(args[0], "%d", &clientID)
		filename := args[1]

		file, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		skipDuplicates, _ := cmd.Flags().GetBool("skip-duplicates")

		scanner := bufio.NewScanner(file)
		imported := 0
		skipped := 0

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Check if it's a CIDR range
			if strings.Contains(line, "/") {
				// Expand CIDR to individual IPs
				ips, err := expandCIDR(line)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Invalid CIDR %s: %v\n", line, err)
					continue
				}

				for _, ip := range ips {
					// Check if duplicate
					if skipDuplicates {
						exists, _ := database.AssetExists(clientID, ip)
						if exists {
							skipped++
							continue
						}
					}

					_, err := database.CreateAsset(clientID, models.AssetTypeIP, ip, nil)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: Failed to import %s: %v\n", ip, err)
						continue
					}
					imported++
				}
			} else {
				// Single asset
				// Check if duplicate
				if skipDuplicates {
					exists, _ := database.AssetExists(clientID, line)
					if exists {
						skipped++
						continue
					}
				}

				// Auto-detect asset type
				assetType := detectAssetType(line)

				_, err := database.CreateAsset(clientID, assetType, line, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to import %s: %v\n", line, err)
					continue
				}

				imported++
			}
		}

		fmt.Printf("✓ Imported %d assets", imported)
		if skipped > 0 {
			fmt.Printf(" (skipped %d duplicates)", skipped)
		}
		fmt.Println()
	},
}

// expandCIDR expands a CIDR notation into individual IP addresses
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// Skip network and broadcast addresses for /24 and larger
		ipStr := ip.String()
		if strings.HasSuffix(ipStr, ".0") || strings.HasSuffix(ipStr, ".255") {
			continue
		}
		ips = append(ips, ipStr)
	}

	return ips, nil
}

// incrementIP increments an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// detectAssetType auto-detects the asset type
func detectAssetType(value string) models.AssetType {
	// Check if it's an IP address
	if net.ParseIP(value) != nil {
		return models.AssetTypeIP
	}

	// Check if it contains a subdomain (has more than one dot)
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return models.AssetTypeSubdomain
	}

	return models.AssetTypeDomain
}

func init() {
	assetListCmd.Flags().Int64("client-id", 0, "Filter by client ID")
	assetListCmd.Flags().String("type", "", "Filter by asset type")
	assetListCmd.Flags().Bool("active-only", false, "Show only active assets")
	assetListCmd.Flags().Bool("export", false, "Export assets as JSON")

	assetImportCmd.Flags().Bool("skip-duplicates", false, "Skip duplicate assets")

	assetCmd.AddCommand(assetAddCmd)
	assetCmd.AddCommand(assetListCmd)
	assetCmd.AddCommand(assetImportCmd)
}
