package models

import (
	"time"
)

// Client represents an organization/client
type Client struct {
	ID            int64     `json:"id" gorm:"primaryKey"`
	Name          string    `json:"name" gorm:"unique;not null"`
	Description   string    `json:"description"`
	PrimaryDomain string    `json:"primary_domain"` // Primary domain for credential monitoring
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AssetType represents the type of asset
type AssetType string

const (
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeIP        AssetType = "ip"
)

// Asset represents a monitored asset
type Asset struct {
	ID            int64     `json:"id" gorm:"primaryKey"`
	ClientID      int64     `json:"client_id" gorm:"not null;index"`
	AssetType     AssetType `json:"asset_type" gorm:"not null"`
	Value         string    `json:"value" gorm:"not null"`
	ParentAssetID *int64    `json:"parent_asset_id" gorm:"index"` // For subdomain -> domain relationship
	Active        bool      `json:"active" gorm:"default:true"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ScanType represents the type of scan
type ScanType string

const (
	ScanTypePort       ScanType = "port_scan"
	ScanTypeTech       ScanType = "tech_stack"
	ScanTypeSubdomain  ScanType = "subdomain_enum"
	ScanTypeCredential ScanType = "credential_breach"
)

// ScanResult stores scan results
type ScanResult struct {
	ID        int64     `json:"id" gorm:"primaryKey"`
	AssetID   int64     `json:"asset_id" gorm:"not null;index"`
	ScanType  ScanType  `json:"scan_type" gorm:"not null"`
	Data      string    `json:"data" gorm:"type:text"` // JSON data
	CreatedAt time.Time `json:"created_at" gorm:"index"`
}

// Change represents a detected change
type Change struct {
	ID          int64     `json:"id" gorm:"primaryKey"`
	ClientID    *int64    `json:"client_id,omitempty" gorm:"index"` // For client-level changes (baseline summaries)
	AssetID     *int64    `json:"asset_id,omitempty" gorm:"index"`  // For asset-level changes (null for client-level)
	ChangeType  string    `json:"change_type" gorm:"not null"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // info, low, medium, high
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	Notified    bool      `json:"notified" gorm:"default:false"`
	CreatedAt   time.Time `json:"created_at" gorm:"index"`
}

// ScheduledJob represents a scheduled monitoring job
type ScheduledJob struct {
	ID           int64     `json:"id" gorm:"primaryKey"`
	ClientID     int64     `json:"client_id" gorm:"not null;index"`
	JobType      string    `json:"job_type" gorm:"not null"` // port_scan, tech_scan, subdomain_enum, all_scan
	CronSchedule string    `json:"cron_schedule" gorm:"not null"`
	Config       string    `json:"config" gorm:"type:text"` // JSON config
	Active       bool      `json:"active" gorm:"default:true"`
	LastRun      *time.Time `json:"last_run"`
	NextRun      *time.Time `json:"next_run"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Webhook represents a notification webhook
type Webhook struct {
	ID          int64     `json:"id" gorm:"primaryKey"`
	ClientID    int64     `json:"client_id" gorm:"not null;index"`
	Name        string    `json:"name" gorm:"not null"`
	WebhookType string    `json:"webhook_type" gorm:"not null"` // slack, discord, teams, generic
	URL         string    `json:"url" gorm:"not null"`
	Active      bool      `json:"active" gorm:"default:true"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
