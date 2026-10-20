package middleware

import (
	"net/http"
	"strings"

	"gin-auth/internal/models"
	"gin-auth/internal/utils"

	"github.com/gin-gonic/gin"
)

const (
	ContextUserIDKey = "userID"
	ContextEmailKey  = "userEmail"
	ContextRoleKey   = "userRole"
)

func AuthMiddleware(jwtManager *utils.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.SendError(c, http.StatusUnauthorized, "Authorization header is required", nil)
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			utils.SendError(c, http.StatusUnauthorized, "Authorization header format must be Bearer {token}", nil)
			c.Abort()
			return
		}

		claims, err := jwtManager.ValidateAccessToken(parts[1])
		if err != nil {
			utils.SendError(c, http.StatusUnauthorized, "Invalid or expired access token", nil)
			c.Abort()
			return
		}

		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextEmailKey, claims.Email)
		c.Set(ContextRoleKey, claims.Role)
		c.Next()
	}
}

func RequireRoles(allowedRoles ...models.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get(ContextRoleKey)
		if !exists {
			utils.SendError(c, http.StatusForbidden, "Access denied: role not found in context", nil)
			c.Abort()
			return
		}

		userRole, ok := roleVal.(models.Role)
		if !ok {
			utils.SendError(c, http.StatusForbidden, "Access denied: invalid role type", nil)
			c.Abort()
			return
		}

		for _, role := range allowedRoles {
			if userRole == role {
				c.Next()
				return
			}
		}

		utils.SendError(c, http.StatusForbidden, "Access denied: insufficient permissions", nil)
		c.Abort()
	}
}
