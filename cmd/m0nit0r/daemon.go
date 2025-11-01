package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run the monitoring daemon",
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the daemon",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Daemon not yet implemented - coming soon!")
	},
}

func init() {
	daemonCmd.AddCommand(daemonStartCmd)
}
