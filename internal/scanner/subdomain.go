package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SubdomainResult represents subdomain enumeration results
type SubdomainResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
	Success    bool     `json:"success"`
	Error      string   `json:"error,omitempty"`
}

// EnumerateSubdomains runs BBOT to enumerate subdomains
func EnumerateSubdomains(domain string, verbose bool) (*SubdomainResult, error) {
	// Get home directory for output
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create output directory
	outputDir := filepath.Join(home, ".m0nit0r", "bbot_scans", strings.ReplaceAll(domain, ".", "_"))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Build BBOT command
	args := []string{
		"-t", domain,
		"-p", "subdomain-enum",
		"-o", outputDir,
		"-y", // Skip prompts
	}

	if verbose {
		args = append(args, "-v")
	}

	cmd := exec.Command("bbot", args...)

	// If verbose, stream output to console
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	// Run BBOT
	if err := cmd.Run(); err != nil {
		return &SubdomainResult{
			Domain:  domain,
			Success: false,
			Error:   fmt.Sprintf("BBOT execution failed: %v", err),
		}, nil
	}

	// Find subdomains.txt (BBOT creates a subdirectory with random name)
	subdomainsFile, err := findSubdomainsFile(outputDir)
	if err != nil {
		return &SubdomainResult{
			Domain:  domain,
			Success: false,
			Error:   fmt.Sprintf("failed to find subdomains.txt: %v", err),
		}, nil
	}

	// Parse subdomains.txt
	subdomains, err := parseSubdomainsFile(subdomainsFile, domain)
	if err != nil {
		return &SubdomainResult{
			Domain:  domain,
			Success: false,
			Error:   fmt.Sprintf("failed to parse results: %v", err),
		}, nil
	}

	return &SubdomainResult{
		Domain:     domain,
		Subdomains: subdomains,
		Count:      len(subdomains),
		Success:    true,
	}, nil
}

// findSubdomainsFile searches for subdomains.txt in the output directory
func findSubdomainsFile(outputDir string) (string, error) {
	var foundPath string
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "subdomains.txt" {
			foundPath = path
			return filepath.SkipAll // Stop walking once found
		}
		return nil
	})

	if err != nil {
		return "", err
	}

	if foundPath == "" {
		return "", fmt.Errorf("subdomains.txt not found in %s", outputDir)
	}

	return foundPath, nil
}

// parseSubdomainsFile reads and parses the subdomains.txt file
func parseSubdomainsFile(filePath, domain string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" && strings.HasSuffix(subdomain, domain) && !seen[subdomain] {
			subdomains = append(subdomains, subdomain)
			seen[subdomain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}

// CompareSubdomains compares two subdomain results
func CompareSubdomains(previous, current *SubdomainResult) *SubdomainChanges {
	prevSet := make(map[string]bool)
	for _, sub := range previous.Subdomains {
		prevSet[sub] = true
	}

	currSet := make(map[string]bool)
	for _, sub := range current.Subdomains {
		currSet[sub] = true
	}

	var newSubdomains, removedSubdomains []string

	// Find new subdomains
	for sub := range currSet {
		if !prevSet[sub] {
			newSubdomains = append(newSubdomains, sub)
		}
	}

	// Find removed subdomains
	for sub := range prevSet {
		if !currSet[sub] {
			removedSubdomains = append(removedSubdomains, sub)
		}
	}

	return &SubdomainChanges{
		NewSubdomains:     newSubdomains,
		RemovedSubdomains: removedSubdomains,
		TotalNew:          len(newSubdomains),
		TotalRemoved:      len(removedSubdomains),
	}
}

// SubdomainChanges represents changes between scans
type SubdomainChanges struct {
	NewSubdomains     []string `json:"new_subdomains"`
	RemovedSubdomains []string `json:"removed_subdomains"`
	TotalNew          int      `json:"total_new"`
	TotalRemoved      int      `json:"total_removed"`
}

// ToJSON converts result to JSON string
func (r *SubdomainResult) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON parses JSON string to SubdomainResult
func SubdomainResultFromJSON(data string) (*SubdomainResult, error) {
	var result SubdomainResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BatchSubdomainResult represents results for multiple domains
type BatchSubdomainResult struct {
	Results map[string]*SubdomainResult `json:"results"` // domain -> result
	Success bool                        `json:"success"`
	Error   string                      `json:"error,omitempty"`
}

// EnumerateSubdomainsBatch runs BBOT on multiple domains at once
func EnumerateSubdomainsBatch(domains []string, verbose bool) (*BatchSubdomainResult, error) {
	if len(domains) == 0 {
		return &BatchSubdomainResult{
			Results: make(map[string]*SubdomainResult),
			Success: true,
		}, nil
	}

	// Get home directory for output
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create unique output directory for this batch
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	outputDir := filepath.Join(home, ".m0nit0r", "bbot_scans", fmt.Sprintf("batch_%s", timestamp))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Build BBOT command with multiple targets
	args := []string{"-t"}
	args = append(args, domains...)
	args = append(args, "-p", "subdomain-enum")
	args = append(args, "-o", outputDir)
	args = append(args, "-y") // Skip prompts

	if verbose {
		args = append(args, "-v")
	}

	cmd := exec.Command("bbot", args...)

	// If verbose, stream output to console
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	// Run BBOT
	if err := cmd.Run(); err != nil {
		return &BatchSubdomainResult{
			Results: make(map[string]*SubdomainResult),
			Success: false,
			Error:   fmt.Sprintf("BBOT execution failed: %v", err),
		}, nil
	}

	// Find and parse subdomains.txt
	subdomainsFile, err := findSubdomainsFile(outputDir)
	if err != nil {
		return &BatchSubdomainResult{
			Results: make(map[string]*SubdomainResult),
			Success: false,
			Error:   fmt.Sprintf("failed to find subdomains.txt: %v", err),
		}, nil
	}

	// Read all subdomains
	file, err := os.Open(subdomainsFile)
	if err != nil {
		return &BatchSubdomainResult{
			Results: make(map[string]*SubdomainResult),
			Success: false,
			Error:   fmt.Sprintf("failed to open subdomains.txt: %v", err),
		}, nil
	}
	defer file.Close()

	// Parse and attribute subdomains to parent domains
	results := make(map[string]*SubdomainResult)
	for _, domain := range domains {
		results[domain] = &SubdomainResult{
			Domain:     domain,
			Subdomains: []string{},
			Count:      0,
			Success:    true,
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}

		// Match subdomain to parent domain
		for _, domain := range domains {
			if strings.HasSuffix(subdomain, domain) {
				// Check if already added (avoid duplicates)
				found := false
				for _, existing := range results[domain].Subdomains {
					if existing == subdomain {
						found = true
						break
					}
				}
				if !found {
					results[domain].Subdomains = append(results[domain].Subdomains, subdomain)
					results[domain].Count++
				}
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return &BatchSubdomainResult{
			Results: results,
			Success: false,
			Error:   fmt.Sprintf("failed to read subdomains.txt: %v", err),
		}, nil
	}

	return &BatchSubdomainResult{
		Results: results,
		Success: true,
	}, nil
}
