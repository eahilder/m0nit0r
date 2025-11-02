package database

import (
	"github.com/errorixlab/m0nit0r/internal/models"
)

// SaveScanResult saves a scan result
func SaveScanResult(assetID int64, scanType models.ScanType, data string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		AssetID:  assetID,
		ScanType: scanType,
		Data:     data,
	}

	if err := DB.Create(result).Error; err != nil {
		return nil, err
	}

	return result, nil
}

// GetLatestScanResult retrieves the most recent scan result for an asset and scan type
func GetLatestScanResult(assetID int64, scanType models.ScanType) (*models.ScanResult, error) {
	var result models.ScanResult
	err := DB.Where("asset_id = ? AND scan_type = ?", assetID, scanType).
		Order("created_at DESC").
		First(&result).Error
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RecordChange records a detected change for an asset
func RecordChange(assetID int64, changeType, description, severity, oldValue, newValue string) error {
	change := &models.Change{
		AssetID:     &assetID,
		ChangeType:  changeType,
		Description: description,
		Severity:    severity,
		OldValue:    oldValue,
		NewValue:    newValue,
		Notified:    false,
	}

	return DB.Create(change).Error
}

// RecordClientChange records a change at the client level (for baseline summaries)
func RecordClientChange(clientID int64, changeType, description, severity string) error {
	change := &models.Change{
		ClientID:    &clientID,
		ChangeType:  changeType,
		Description: description,
		Severity:    severity,
		Notified:    false,
	}

	return DB.Create(change).Error
}

// HasClientBaseline checks if a client has been baselined
func HasClientBaseline(clientID int64) (bool, error) {
	var count int64
	err := DB.Model(&models.Change{}).
		Where("client_id = ? AND change_type LIKE 'baseline_%'", clientID).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// HasScanTypeBaseline checks if a specific scan type has been baselined for a client
func HasScanTypeBaseline(clientID int64, scanType string) (bool, error) {
	var count int64

	// Map scan types to change type patterns
	var pattern string
	switch scanType {
	case "subdomains":
		pattern = "baseline_subdomain%"
	case "ports":
		pattern = "baseline_port%"
	case "credentials":
		pattern = "baseline_credential%"
	case "tech":
		pattern = "baseline_tech%"
	default:
		// For "all" or unknown, check any baseline
		return HasClientBaseline(clientID)
	}

	err := DB.Model(&models.Change{}).
		Where("(client_id = ? OR asset_id IN (SELECT id FROM assets WHERE client_id = ?)) AND change_type LIKE ?",
			clientID, clientID, pattern).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// ListChanges retrieves changes with optional filters
func ListChanges(clientID *int64, assetID *int64, unnotifiedOnly bool) ([]models.Change, error) {
	var changes []models.Change
	query := DB.Order("created_at DESC")

	if assetID != nil {
		query = query.Where("asset_id = ?", *assetID)
	} else if clientID != nil {
		// Get changes directly for client OR for assets belonging to client
		query = query.Where("client_id = ? OR asset_id IN (SELECT id FROM assets WHERE client_id = ?)", *clientID, *clientID)
	}

	if unnotifiedOnly {
		query = query.Where("notified = ?", false)
	}

	if err := query.Find(&changes).Error; err != nil {
		return nil, err
	}

	return changes, nil
}

// MarkChangesNotified marks changes as notified
func MarkChangesNotified(changeIDs []int64) error {
	return DB.Model(&models.Change{}).
		Where("id IN ?", changeIDs).
		Update("notified", true).Error
}
