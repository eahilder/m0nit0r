package database

import (
	"github.com/errorixlab/m0nit0r/internal/models"
)

// CreateClient creates a new client
func CreateClient(name, description string) (*models.Client, error) {
	client := &models.Client{
		Name:        name,
		Description: description,
	}

	if err := DB.Create(client).Error; err != nil {
		return nil, err
	}

	return client, nil
}

// GetClient retrieves a client by ID
func GetClient(id int64) (*models.Client, error) {
	var client models.Client
	if err := DB.First(&client, id).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

// ListClients retrieves all clients
func ListClients() ([]models.Client, error) {
	var clients []models.Client
	if err := DB.Order("created_at DESC").Find(&clients).Error; err != nil {
		return nil, err
	}
	return clients, nil
}

// UpdateClient updates a client
func UpdateClient(client *models.Client) error {
	return DB.Save(client).Error
}

// DeleteClient deletes a client
func DeleteClient(id int64) error {
	return DB.Delete(&models.Client{}, id).Error
}
