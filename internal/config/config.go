package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the application configuration
type Config struct {
	DehashedAPIKey string `json:"dehashed_api_key,omitempty"`
	OathnetAPIKey  string `json:"oathnet_api_key,omitempty"`
}

var (
	globalConfig *Config
	configPath   string
)

// init initializes the config path
func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		configPath = "config.json" // Fallback to current directory
	} else {
		configPath = filepath.Join(home, ".m0nit0r", "config.json")
	}
}

// Load loads the configuration from file
func Load() (*Config, error) {
	if globalConfig != nil {
		return globalConfig, nil
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return empty config if file doesn't exist
		globalConfig = &Config{}
		return globalConfig, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	globalConfig = &cfg
	return globalConfig, nil
}

// Save saves the configuration to file
func Save(cfg *Config) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil { // 0600 for security
		return fmt.Errorf("failed to write config: %w", err)
	}

	globalConfig = cfg
	return nil
}

// Get returns the current configuration (loads if not already loaded)
func Get() (*Config, error) {
	if globalConfig != nil {
		return globalConfig, nil
	}
	return Load()
}

// GetConfigPath returns the path to the config file
func GetConfigPath() string {
	return configPath
}

// HasCredentialScanningEnabled checks if credential scanning is configured
func HasCredentialScanningEnabled() bool {
	cfg, err := Get()
	if err != nil {
		return false
	}
	return cfg.DehashedAPIKey != "" || cfg.OathnetAPIKey != ""
}

// HasDehashedConfigured checks if DeHashed API is configured
func HasDehashedConfigured() bool {
	cfg, err := Get()
	if err != nil {
		return false
	}
	return cfg.DehashedAPIKey != ""
}

// HasOathnetConfigured checks if OathNet API is configured
func HasOathnetConfigured() bool {
	cfg, err := Get()
	if err != nil {
		return false
	}
	return cfg.OathnetAPIKey != ""
}
