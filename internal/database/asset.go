package database

import (
	"github.com/errorixlab/m0nit0r/internal/models"
)

// CreateAsset creates a new asset
func CreateAsset(clientID int64, assetType models.AssetType, value string, parentAssetID *int64) (*models.Asset, error) {
	asset := &models.Asset{
		ClientID:      clientID,
		AssetType:     assetType,
		Value:         value,
		ParentAssetID: parentAssetID,
		Active:        true,
	}

	if err := DB.Create(asset).Error; err != nil {
		return nil, err
	}

	return asset, nil
}

// GetAsset retrieves an asset by ID
func GetAsset(id int64) (*models.Asset, error) {
	var asset models.Asset
	if err := DB.First(&asset, id).Error; err != nil {
		return nil, err
	}
	return &asset, nil
}

// ListAssets retrieves assets with optional filters
func ListAssets(clientID *int64, assetType *models.AssetType, activeOnly bool) ([]models.Asset, error) {
	var assets []models.Asset
	query := DB.Order("created_at DESC")

	if clientID != nil {
		query = query.Where("client_id = ?", *clientID)
	}
	if assetType != nil {
		query = query.Where("asset_type = ?", *assetType)
	}
	if activeOnly {
		query = query.Where("active = ?", true)
	}

	if err := query.Find(&assets).Error; err != nil {
		return nil, err
	}

	return assets, nil
}

// DeactivateAsset marks an asset as inactive
func DeactivateAsset(id int64) error {
	return DB.Model(&models.Asset{}).Where("id = ?", id).Update("active", false).Error
}

// DeleteAsset deletes an asset
func DeleteAsset(id int64) error {
	return DB.Delete(&models.Asset{}, id).Error
}

// AssetExists checks if an asset with the given value already exists for a client
func AssetExists(clientID int64, value string) (bool, error) {
	var count int64
	err := DB.Model(&models.Asset{}).
		Where("client_id = ? AND value = ?", clientID, value).
		Count(&count).Error
	return count > 0, err
}
