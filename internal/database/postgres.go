package database

import (
	"fmt"
	"log"

	"gin-auth/internal/config"
	"gin-auth/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ConnectPostgres(cfg *config.Config) (*gorm.DB, error) {
	logLevel := logger.Info
	if cfg.GinMode == "release" {
		logLevel = logger.Warn
	}

	db, err := gorm.Open(postgres.Open(cfg.GetDSN()), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Auto migrate models
	if err := db.AutoMigrate(&models.User{}, &models.RefreshToken{}); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate database schemas: %w", err)
	}

	log.Println("Connected to PostgreSQL and migrated database schemas successfully")
	return db, nil
}
