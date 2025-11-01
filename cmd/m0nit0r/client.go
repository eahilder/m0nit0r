package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/errorixlab/m0nit0r/internal/database"
	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Manage clients/organizations",
}

var clientAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new client",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		description, _ := cmd.Flags().GetString("description")
		primaryDomain, _ := cmd.Flags().GetString("primary-domain")

		client, err := database.CreateClient(name, description)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create client: %v\n", err)
			os.Exit(1)
		}

		// Update primary domain if provided
		if primaryDomain != "" {
			client.PrimaryDomain = primaryDomain
			if err := database.UpdateClient(client); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to set primary domain: %v\n", err)
			}
		}

		fmt.Printf("✓ Created client: %s (ID: %d)\n", client.Name, client.ID)
		if primaryDomain != "" {
			fmt.Printf("  Primary domain: %s\n", primaryDomain)
		}
	},
}

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all clients",
	Run: func(cmd *cobra.Command, args []string) {
		clients, err := database.ListClients()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list clients: %v\n", err)
			os.Exit(1)
		}

		if len(clients) == 0 {
			fmt.Println("No clients found")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tPRIMARY DOMAIN\tDESCRIPTION\tCREATED")
		fmt.Fprintln(w, "--\t----\t--------------\t-----------\t-------")

		for _, client := range clients {
			primaryDomain := client.PrimaryDomain
			if primaryDomain == "" {
				primaryDomain = "-"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
				client.ID,
				client.Name,
				primaryDomain,
				client.Description,
				client.CreatedAt.Format("2006-01-02 15:04"),
			)
		}

		w.Flush()
	},
}

var clientDeleteCmd = &cobra.Command{
	Use:   "delete <client_id>",
	Short: "Delete a client",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var clientID int64
		fmt.Sscanf(args[0], "%d", &clientID)

		if err := database.DeleteClient(clientID); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete client: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Deleted client %d\n", clientID)
	},
}

func init() {
	clientAddCmd.Flags().StringP("description", "d", "", "Client description")
	clientAddCmd.Flags().String("primary-domain", "", "Primary domain for credential monitoring")

	clientCmd.AddCommand(clientAddCmd)
	clientCmd.AddCommand(clientListCmd)
	clientCmd.AddCommand(clientDeleteCmd)
}
