package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/spf13/cobra"
)

var changesCmd = &cobra.Command{
	Use:   "changes",
	Short: "View detected changes",
}

var changesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List detected changes",
	Run: func(cmd *cobra.Command, args []string) {
		var clientID *int64
		clientIDFlag, _ := cmd.Flags().GetInt64("client-id")
		if clientIDFlag > 0 {
			clientID = &clientIDFlag
		}

		var assetID *int64
		assetIDFlag, _ := cmd.Flags().GetInt64("asset-id")
		if assetIDFlag > 0 {
			assetID = &assetIDFlag
		}

		unnotified, _ := cmd.Flags().GetBool("unnotified")

		changes, err := database.ListChanges(clientID, assetID, unnotified)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list changes: %v\n", err)
			os.Exit(1)
		}

		if len(changes) == 0 {
			fmt.Println("No changes found")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tASSET_ID\tTYPE\tDESCRIPTION\tSEVERITY\tCREATED")
		fmt.Fprintln(w, "--\t--------\t----\t-----------\t--------\t-------")

		for _, change := range changes {
			fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%s\n",
				change.ID,
				change.AssetID,
				change.ChangeType,
				truncate(change.Description, 40),
				change.Severity,
				change.CreatedAt.Format("2006-01-02 15:04"),
			)
		}

		w.Flush()
	},
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func init() {
	changesListCmd.Flags().Int64("client-id", 0, "Filter by client ID")
	changesListCmd.Flags().Int64("asset-id", 0, "Filter by asset ID")
	changesListCmd.Flags().Bool("unnotified", false, "Show only unnotified changes")

	changesCmd.AddCommand(changesListCmd)
}
