package main

import (
	"fmt"
	"log"

	"gin-auth/internal/config"
	"gin-auth/internal/database"
	"gin-auth/internal/handlers"
	"gin-auth/internal/repositories"
	"gin-auth/internal/routes"
	"gin-auth/internal/services"
	"gin-auth/internal/utils"
)

func main() {
	// 1. Load Configuration
	cfg := config.LoadConfig()

	// 2. Connect Database & Run Auto-Migration
	db, err := database.ConnectPostgres(cfg)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	// 3. Initialize Utilities, Repositories, Services & Handlers
	jwtManager := utils.NewJWTManager(cfg)
	userRepo := repositories.NewUserRepository(db)
	authService := services.NewAuthService(userRepo, jwtManager)
	authHandler := handlers.NewAuthHandler(authService)

	// 4. Setup Gin Router
	router := routes.SetupRouter(cfg, authHandler, jwtManager)

	// 5. Start Server
	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Server starting on http://localhost%s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
