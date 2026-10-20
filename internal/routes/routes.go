package routes

import (
	"net/http"
	"time"

	"gin-auth/internal/config"
	"gin-auth/internal/handlers"
	"gin-auth/internal/middleware"
	"gin-auth/internal/models"
	"gin-auth/internal/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRouter(
	cfg *config.Config,
	authHandler *handlers.AuthHandler,
	jwtManager *utils.JWTManager,
) *gin.Engine {
	gin.SetMode(cfg.GinMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// CORS Setup
	r.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSAllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Healthcheck endpoint
	r.GET("/health", func(c *gin.Context) {
		utils.SendSuccess(c, http.StatusOK, "Server is healthy", gin.H{
			"status":    "UP",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	api := r.Group("/api/v1")
	{
		// Public Auth Routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
			auth.POST("/logout", authHandler.Logout)

			// Protected Auth Routes
			authProtected := auth.Group("")
			authProtected.Use(middleware.AuthMiddleware(jwtManager))
			{
				authProtected.GET("/me", authHandler.Me)
			}
		}

		// Admin Protected Routes (RBAC: Admin Only)
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(jwtManager), middleware.RequireRoles(models.RoleAdmin))
		{
			admin.GET("/users", authHandler.GetAllUsers)
			admin.PATCH("/users/:id/role", authHandler.UpdateUserRole)
		}
	}

	return r
}
