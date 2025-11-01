package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scheduleCmd = &cobra.Command{
	Use:   "schedule",
	Short: "Manage scheduled monitoring jobs",
}

var scheduleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scheduled jobs",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scheduler not yet implemented - coming soon!")
	},
}

func init() {
	scheduleCmd.AddCommand(scheduleListCmd)
}
