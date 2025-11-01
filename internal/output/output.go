package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manager handles output file generation
type Manager struct {
	baseDir string
}

// NewManager creates a new output manager
func NewManager() (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	baseDir := filepath.Join(home, ".m0nit0r", "output")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &Manager{baseDir: baseDir}, nil
}

// SaveScanResult saves scan results to a file
func (m *Manager) SaveScanResult(clientName, assetValue, scanType string, data interface{}, hasChanges bool) (string, error) {
	// Create client directory
	clientDir := filepath.Join(m.baseDir, clientName)
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		return "", err
	}

	// Generate filename
	timestamp := time.Now().Format("20060102_150405")
	suffix := ""
	if hasChanges {
		suffix = "_CHANGES"
	}
	filename := fmt.Sprintf("%s_%s_%s%s.json", timestamp, scanType, assetValue, suffix)
	filepath := filepath.Join(clientDir, filename)

	// Convert to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	// Write file
	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return "", err
	}

	return filepath, nil
}

// SaveChanges saves detected changes to a file
func (m *Manager) SaveChanges(clientName, assetValue, scanType string, changes interface{}) (string, error) {
	clientDir := filepath.Join(m.baseDir, clientName)
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_%s_changes.json", timestamp, scanType, assetValue)
	filepath := filepath.Join(clientDir, filename)

	jsonData, err := json.MarshalIndent(changes, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		return "", err
	}

	return filepath, nil
}

// GenerateChangeReport generates a markdown report of changes
func (m *Manager) GenerateChangeReport(clientName, assetValue string, changes []ChangeItem) (string, error) {
	clientDir := filepath.Join(m.baseDir, clientName)
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		return "", err
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_CHANGE_REPORT_%s.md", timestamp, assetValue)
	filepath := filepath.Join(clientDir, filename)

	// Generate markdown content
	content := fmt.Sprintf("# Change Report: %s\n\n", assetValue)
	content += fmt.Sprintf("Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	content += fmt.Sprintf("## Summary\n\nTotal Changes: %d\n\n", len(changes))

	// Group by change type
	byType := make(map[string][]ChangeItem)
	for _, change := range changes {
		byType[change.ChangeType] = append(byType[change.ChangeType], change)
	}

	// Write changes by type
	for changeType, items := range byType {
		content += fmt.Sprintf("### %s (%d)\n\n", changeType, len(items))
		for _, item := range items {
			content += fmt.Sprintf("- **%s** (%s)\n", item.Description, item.Severity)
			if item.OldValue != "" {
				content += fmt.Sprintf("  - Old: `%s`\n", item.OldValue)
			}
			if item.NewValue != "" {
				content += fmt.Sprintf("  - New: `%s`\n", item.NewValue)
			}
			content += "\n"
		}
	}

	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return "", err
	}

	return filepath, nil
}

// ChangeItem represents a single change for reporting
type ChangeItem struct {
	ChangeType  string
	Description string
	Severity    string
	OldValue    string
	NewValue    string
}
