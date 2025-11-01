package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CredentialResult represents credential breach scan results
type CredentialResult struct {
	Domain    string             `json:"domain"`
	Dehashed  *DehashedResult    `json:"dehashed,omitempty"`
	Oathnet   *OathnetResult     `json:"oathnet,omitempty"`
	Emails    []string           `json:"emails"`
	Passwords []string           `json:"passwords"` // Cleartext passwords found
	Hashes    []CredentialHash   `json:"hashes"`
	Success   bool               `json:"success"`
	Error     string             `json:"error,omitempty"`
}

// CredentialHash represents a hashed password with metadata
type CredentialHash struct {
	Hash     string `json:"hash"`
	Email    string `json:"email"`
	Source   string `json:"source"` // "dehashed" or "oathnet"
	HashType string `json:"hash_type,omitempty"`
}

// DehashedResult represents DeHashed API results
type DehashedResult struct {
	TotalResults int                  `json:"total_results"`
	Passwords    int                  `json:"passwords"`
	Hashes       int                  `json:"hashes"`
	Entries      []DehashedEntry      `json:"entries,omitempty"`
}

// DehashedEntry represents a single DeHashed entry
type DehashedEntry struct {
	Email          string `json:"email"`
	Password       string `json:"password,omitempty"`
	HashedPassword string `json:"hashed_password,omitempty"`
	Database       string `json:"database,omitempty"`
}

// OathnetResult represents OathNet API results
type OathnetResult struct {
	BreachResults  int                 `json:"breach_results"`
	StealerResults int                 `json:"stealer_results"`
	Passwords      int                 `json:"passwords"`
	Hashes         int                 `json:"hashes"`
	Entries        []OathnetEntry      `json:"entries,omitempty"`
}

// OathnetEntry represents a single OathNet entry
type OathnetEntry struct {
	Email        string `json:"email"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	Source       string `json:"source"` // "breach" or "stealer"
	Database     string `json:"database,omitempty"`
}

// ScanCredentials scans for breached credentials using configured APIs
func ScanCredentials(domain, dehashedKey, oathnetKey string) (*CredentialResult, error) {
	result := &CredentialResult{
		Domain:    domain,
		Emails:    []string{},
		Passwords: []string{},
		Hashes:    []CredentialHash{},
		Success:   true,
	}

	emailSet := make(map[string]bool)
	passwordSet := make(map[string]bool)

	dehashedSuccess := false
	oathnetSuccess := false

	// Scan DeHashed if key is provided
	if dehashedKey != "" {
		dehashedResult, err := scanDehashed(domain, dehashedKey)
		if err != nil {
			result.Error = fmt.Sprintf("DeHashed error: %v", err)
		} else {
			dehashedSuccess = true
			result.Dehashed = dehashedResult

			// Collect unique emails and passwords
			for _, entry := range dehashedResult.Entries {
				if entry.Email != "" {
					emailSet[entry.Email] = true
				}
				if entry.Password != "" {
					passwordSet[entry.Password] = true
				}
				if entry.HashedPassword != "" {
					result.Hashes = append(result.Hashes, CredentialHash{
						Hash:   entry.HashedPassword,
						Email:  entry.Email,
						Source: "dehashed",
					})
				}
			}
		}
	}

	// Scan OathNet if key is provided
	if oathnetKey != "" {
		oathnetResult, err := scanOathnet(domain, oathnetKey)
		if err != nil {
			if result.Error != "" {
				result.Error += "; "
			}
			result.Error += fmt.Sprintf("OathNet error: %v", err)
		} else {
			oathnetSuccess = true
			result.Oathnet = oathnetResult

			// Collect unique emails and passwords
			for _, entry := range oathnetResult.Entries {
				if entry.Email != "" {
					emailSet[entry.Email] = true
				}
				if entry.Password != "" {
					passwordSet[entry.Password] = true
				}
				if entry.PasswordHash != "" {
					hashType := identifyHashType(entry.PasswordHash)
					result.Hashes = append(result.Hashes, CredentialHash{
						Hash:     entry.PasswordHash,
						Email:    entry.Email,
						Source:   "oathnet",
						HashType: hashType,
					})
				}
			}
		}
	}

	// Convert sets to slices
	for email := range emailSet {
		result.Emails = append(result.Emails, email)
	}
	for password := range passwordSet {
		result.Passwords = append(result.Passwords, password)
	}

	// Determine overall success: successful if at least one API worked or we got results
	if !dehashedSuccess && !oathnetSuccess {
		result.Success = false
	} else if len(result.Emails) == 0 && len(result.Passwords) == 0 && len(result.Hashes) == 0 {
		// Both APIs ran but got no results
		result.Success = true // Still consider it successful (just no breaches found)
		if result.Error == "" {
			result.Error = "No breached credentials found"
		}
	} else {
		result.Success = true // At least one API worked and we have results
	}

	return result, nil
}

// scanDehashed queries the DeHashed API
func scanDehashed(domain, apiKey string) (*DehashedResult, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	reqBody := map[string]interface{}{
		"query":    fmt.Sprintf("domain:%s", domain),
		"page":     1,
		"size":     10000,
		"wildcard": false,
		"regex":    false,
		"de_dupe":  true,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.dehashed.com/v2/search", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DeHashed-Api-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Success bool `json:"success"`
		Message string `json:"message,omitempty"`
		Entries []struct {
			Email          interface{} `json:"email"` // Can be string or array
			Password       interface{} `json:"password"` // Can be string or array
			HashedPassword interface{} `json:"hashed_password"` // Can be string or array
			Database       interface{} `json:"database_name"` // Can be string or array
		} `json:"entries"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("API error: %s", apiResp.Message)
	}

	result := &DehashedResult{
		TotalResults: len(apiResp.Entries),
		Entries:      []DehashedEntry{},
	}

	for _, entry := range apiResp.Entries {
		// Helper function to extract string from interface (string or array)
		extractString := func(v interface{}) string {
			switch val := v.(type) {
			case string:
				return val
			case []interface{}:
				if len(val) > 0 {
					if s, ok := val[0].(string); ok {
						return s
					}
				}
			}
			return ""
		}

		email := extractString(entry.Email)
		if email == "" || email == "None" {
			continue
		}

		password := extractString(entry.Password)
		hashedPassword := extractString(entry.HashedPassword)
		database := extractString(entry.Database)

		resultEntry := DehashedEntry{
			Email:    email,
			Database: database,
		}

		if password != "" && password != "None" {
			resultEntry.Password = password
			result.Passwords++
		}

		if hashedPassword != "" && hashedPassword != "None" {
			resultEntry.HashedPassword = hashedPassword
			result.Hashes++
		}

		result.Entries = append(result.Entries, resultEntry)
	}

	return result, nil
}

// scanOathnet queries the OathNet API
func scanOathnet(domain, apiKey string) (*OathnetResult, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	result := &OathnetResult{
		Entries: []OathnetEntry{},
	}

	// Search breach database
	breachEntries, err := oathnetSearchBreach(client, domain, apiKey)
	if err != nil {
		return nil, fmt.Errorf("breach search failed: %w", err)
	}
	result.BreachResults = len(breachEntries)
	result.Entries = append(result.Entries, breachEntries...)

	// Search stealer logs
	stealerEntries, err := oathnetSearchStealer(client, domain, apiKey)
	if err != nil {
		return nil, fmt.Errorf("stealer search failed: %w", err)
	}
	result.StealerResults = len(stealerEntries)
	result.Entries = append(result.Entries, stealerEntries...)

	// Count passwords and hashes
	for _, entry := range result.Entries {
		if entry.Password != "" {
			result.Passwords++
		}
		if entry.PasswordHash != "" {
			result.Hashes++
		}
	}

	return result, nil
}

// oathnetSearchBreach searches OathNet breach database
func oathnetSearchBreach(client *http.Client, domain, apiKey string) ([]OathnetEntry, error) {
	var entries []OathnetEntry
	cursor := ""

	for {
		url := fmt.Sprintf("https://oathnet.org/api/service/search-breach/?q=%s", domain)
		if cursor != "" {
			url += fmt.Sprintf("&cursor=%s", cursor)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
		}

		var apiResp struct {
			Success bool `json:"success"`
			Data    struct {
				Results []struct {
					Email        string `json:"email"`
					Password     string `json:"password"`
					PasswordHash string `json:"password_hash"`
					DBName       string `json:"dbname"`
				} `json:"results"`
				Cursor string `json:"cursor"`
			} `json:"data"`
		}

		if err := json.Unmarshal(body, &apiResp); err != nil {
			return nil, err
		}

		if !apiResp.Success {
			break
		}

		for _, result := range apiResp.Data.Results {
			if result.Email == "" || result.Email == "N/A" {
				continue
			}

			entry := OathnetEntry{
				Email:    result.Email,
				Source:   "breach",
				Database: result.DBName,
			}

			if result.Password != "" && result.Password != "N/A" {
				entry.Password = result.Password
			}

			if result.PasswordHash != "" && result.PasswordHash != "N/A" {
				entry.PasswordHash = result.PasswordHash
			}

			entries = append(entries, entry)
		}

		cursor = apiResp.Data.Cursor
		if cursor == "" {
			break
		}

		time.Sleep(500 * time.Millisecond) // Rate limiting
	}

	return entries, nil
}

// oathnetSearchStealer searches OathNet stealer logs
func oathnetSearchStealer(client *http.Client, domain, apiKey string) ([]OathnetEntry, error) {
	var entries []OathnetEntry
	cursor := ""

	for {
		url := fmt.Sprintf("https://oathnet.org/api/service/search-stealer/?q=%s", domain)
		if cursor != "" {
			url += fmt.Sprintf("&cursor=%s", cursor)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
		}

		var apiResp struct {
			Success bool `json:"success"`
			Data    struct {
				Results []struct {
					Email interface{} `json:"email"` // Can be string or array
					LOG   string      `json:"LOG"`
				} `json:"results"`
				Cursor string `json:"cursor"`
			} `json:"data"`
		}

		if err := json.Unmarshal(body, &apiResp); err != nil {
			return nil, err
		}

		if !apiResp.Success {
			break
		}

		for _, result := range apiResp.Data.Results {
			// Parse stealer log
			_, username, password := parseStealerLog(result.LOG)

			// Extract email
			email := ""
			switch v := result.Email.(type) {
			case string:
				email = v
			case []interface{}:
				if len(v) > 0 {
					if s, ok := v[0].(string); ok {
						email = s
					}
				}
			}

			if email == "" || email == "N/A" {
				email = username
			}

			if email == "" || email == "N/A" {
				continue
			}

			entry := OathnetEntry{
				Email:  email,
				Source: "stealer",
			}

			if password != "" && password != "N/A" {
				entry.Password = password
			}

			entries = append(entries, entry)
		}

		cursor = apiResp.Data.Cursor
		if cursor == "" {
			break
		}

		time.Sleep(500 * time.Millisecond) // Rate limiting
	}

	return entries, nil
}

// parseStealerLog parses stealer LOG field to extract URL, username, and password
func parseStealerLog(log string) (url, username, password string) {
	if log == "" {
		return "", "", ""
	}

	// Try pipe separator first (url|username|password)
	if len(log) > 0 && log[0] != '|' {
		parts := splitBy(log, '|')
		if len(parts) == 3 {
			return parts[0], parts[1], parts[2]
		} else if len(parts) == 2 {
			return "", parts[0], parts[1]
		}
	}

	// Try colon separator (username:password)
	parts := splitBy(log, ':')
	if len(parts) >= 2 {
		username = parts[0]
		password = parts[1]
	}

	return "", username, password
}

// splitBy splits a string by a separator
func splitBy(s string, sep rune) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

// identifyHashType identifies hash type based on length and format
func identifyHashType(hash string) string {
	if hash == "" || hash == "N/A" {
		return "unknown"
	}

	hashLen := len(hash)

	// Check for special markers
	if len(hash) > 0 && hash[0] == '$' {
		if hashLen > 4 {
			if hash[:5] == "$2a$" || hash[:5] == "$2b$" || hash[:5] == "$2y$" {
				return "bcrypt"
			} else if hash[:3] == "$6$" {
				return "SHA512crypt"
			} else if hash[:3] == "$5$" {
				return "SHA256crypt"
			} else if hash[:3] == "$1$" {
				return "MD5crypt"
			}
		}
		if len(hash) > 7 && hash[:7] == "$argon2" {
			return "Argon2"
		}
		if len(hash) > 5 && (hash[:5] == "sha1$" || hash[:5] == "sha256$" || hash[:4] == "md5$") {
			return "Django"
		}
	}

	// Check for salted hashes (hash:salt format)
	if containsChar(hash, ':') {
		parts := splitBy(hash, ':')
		if len(parts) == 2 {
			hashPartLen := len(parts[1])
			switch hashPartLen {
			case 32:
				return "MD5_salted"
			case 40:
				return "SHA1_salted"
			case 64:
				return "SHA256_salted"
			}
		}
		return "salted"
	}

	// Check for raw hashes (hex only)
	if isHex(hash) {
		switch hashLen {
		case 32:
			return "MD5"
		case 40:
			return "SHA1"
		case 64:
			return "SHA256"
		case 128:
			return "SHA512"
		}
	}

	return fmt.Sprintf("unknown_%d", hashLen)
}

// containsChar checks if a string contains a character
func containsChar(s string, c rune) bool {
	for _, ch := range s {
		if ch == c {
			return true
		}
	}
	return false
}

// isHex checks if a string contains only hexadecimal characters
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// CompareCredentials compares two credential scan results
func CompareCredentials(previous, current *CredentialResult) *CredentialChanges {
	prevEmails := make(map[string]bool)
	for _, email := range previous.Emails {
		prevEmails[email] = true
	}

	prevPasswords := make(map[string]bool)
	for _, password := range previous.Passwords {
		prevPasswords[password] = true
	}

	var newEmails, newPasswords []string

	for _, email := range current.Emails {
		if !prevEmails[email] {
			newEmails = append(newEmails, email)
		}
	}

	for _, password := range current.Passwords {
		if !prevPasswords[password] {
			newPasswords = append(newPasswords, password)
		}
	}

	return &CredentialChanges{
		NewEmails:    newEmails,
		NewPasswords: newPasswords,
		TotalNew:     len(newEmails) + len(newPasswords),
	}
}

// CredentialChanges represents changes between credential scans
type CredentialChanges struct {
	NewEmails    []string `json:"new_emails"`
	NewPasswords []string `json:"new_passwords"`
	TotalNew     int      `json:"total_new"`
}

// ToJSON converts result to JSON string
func (r *CredentialResult) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// CredentialResultFromJSON parses JSON string to CredentialResult
func CredentialResultFromJSON(data string) (*CredentialResult, error) {
	var result CredentialResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
