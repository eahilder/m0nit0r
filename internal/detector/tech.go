package detector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TechResult represents technology detection results
type TechResult struct {
	URL          string            `json:"url"`
	Technologies map[string]string `json:"technologies"`
	Headers      map[string]string `json:"headers"`
	Success      bool              `json:"success"`
	Error        string            `json:"error,omitempty"`
}

// DetectTech detects technologies on a domain
func DetectTech(domain string) (*TechResult, error) {
	// Ensure URL has scheme
	url := domain
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		// Try HTTP if HTTPS fails
		if strings.HasPrefix(url, "https://") {
			url = "http://" + strings.TrimPrefix(url, "https://")
			resp, err = client.Get(url)
			if err != nil {
				return &TechResult{
					URL:     url,
					Success: false,
					Error:   fmt.Sprintf("request failed: %v", err),
				}, nil
			}
		} else {
			return &TechResult{
				URL:     url,
				Success: false,
				Error:   fmt.Sprintf("request failed: %v", err),
			}, nil
		}
	}
	defer resp.Body.Close()

	// Extract headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	// Detect technologies
	technologies := make(map[string]string)

	// Server header
	if server, ok := headers["server"]; ok {
		technologies["server"] = server
		technologies["web_server"] = identifyWebServer(server)
	}

	// Powered-by header
	if poweredBy, ok := headers["x-powered-by"]; ok {
		technologies["powered_by"] = poweredBy
	}

	// Security headers
	technologies["security_headers"] = detectSecurityHeaders(headers)

	return &TechResult{
		URL:          url,
		Technologies: technologies,
		Headers:      headers,
		Success:      true,
	}, nil
}

// identifyWebServer identifies the web server from the Server header
func identifyWebServer(server string) string {
	server = strings.ToLower(server)

	if strings.Contains(server, "nginx") {
		return "Nginx"
	} else if strings.Contains(server, "apache") {
		return "Apache"
	} else if strings.Contains(server, "cloudflare") {
		return "Cloudflare"
	} else if strings.Contains(server, "microsoft-iis") {
		return "IIS"
	}

	return "Unknown"
}

// detectSecurityHeaders checks for common security headers
func detectSecurityHeaders(headers map[string]string) string {
	securityHeaders := []string{
		"strict-transport-security",
		"x-frame-options",
		"x-content-type-options",
		"content-security-policy",
		"x-xss-protection",
	}

	present := []string{}
	missing := []string{}

	for _, header := range securityHeaders {
		if _, ok := headers[header]; ok {
			present = append(present, header)
		} else {
			missing = append(missing, header)
		}
	}

	if len(missing) > 0 {
		return fmt.Sprintf("Missing: %s", strings.Join(missing, ", "))
	}

	return "All present"
}

// CompareTech compares two technology detection results
func CompareTech(previous, current *TechResult) *TechChanges {
	var newTech, removedTech, changedTech []TechChange

	// Check for new and changed technologies
	for key, currVal := range current.Technologies {
		if prevVal, exists := previous.Technologies[key]; exists {
			if prevVal != currVal {
				changedTech = append(changedTech, TechChange{
					Category: key,
					OldValue: prevVal,
					NewValue: currVal,
				})
			}
		} else {
			newTech = append(newTech, TechChange{
				Category: key,
				NewValue: currVal,
			})
		}
	}

	// Check for removed technologies
	for key, prevVal := range previous.Technologies {
		if _, exists := current.Technologies[key]; !exists {
			removedTech = append(removedTech, TechChange{
				Category: key,
				OldValue: prevVal,
			})
		}
	}

	return &TechChanges{
		NewTech:     newTech,
		RemovedTech: removedTech,
		ChangedTech: changedTech,
		TotalNew:    len(newTech),
		TotalRemoved: len(removedTech),
		TotalChanged: len(changedTech),
	}
}

// TechChanges represents changes in technology stack
type TechChanges struct {
	NewTech      []TechChange `json:"new_tech"`
	RemovedTech  []TechChange `json:"removed_tech"`
	ChangedTech  []TechChange `json:"changed_tech"`
	TotalNew     int          `json:"total_new"`
	TotalRemoved int          `json:"total_removed"`
	TotalChanged int          `json:"total_changed"`
}

// TechChange represents a single technology change
type TechChange struct {
	Category string `json:"category"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// ToJSON converts result to JSON string
func (r *TechResult) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// TechResultFromJSON parses JSON string to TechResult
func TechResultFromJSON(data string) (*TechResult, error) {
	var result TechResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
