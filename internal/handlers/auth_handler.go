package handlers

import (
	"errors"
	"net/http"

	"gin-auth/internal/dto"
	"gin-auth/internal/middleware"
	"gin-auth/internal/services"
	"gin-auth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	authService services.AuthService
}

func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles POST /api/v1/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	res, err := h.authService.Register(req)
	if err != nil {
		if errors.Is(err, services.ErrEmailAlreadyExists) {
			utils.SendError(c, http.StatusConflict, err.Error(), nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to register user", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusCreated, "User registered successfully", res)
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	res, err := h.authService.Login(req)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			utils.SendError(c, http.StatusUnauthorized, err.Error(), nil)
			return
		}
		if errors.Is(err, services.ErrAccountDeactivated) {
			utils.SendError(c, http.StatusForbidden, err.Error(), nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to login", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Login successful", res)
}

// Refresh handles POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	res, err := h.authService.RefreshToken(req)
	if err != nil {
		if errors.Is(err, services.ErrInvalidRefresh) || errors.Is(err, services.ErrAccountDeactivated) {
			utils.SendError(c, http.StatusUnauthorized, err.Error(), nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to refresh token", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Token refreshed successfully", res)
}

// Logout handles POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	if err := h.authService.Logout(req.RefreshToken); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "Failed to logout", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Logged out successfully", nil)
}

// Me handles GET /api/v1/auth/me
func (h *AuthHandler) Me(c *gin.Context) {
	userIDVal, exists := c.Get(middleware.ContextUserIDKey)
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		utils.SendError(c, http.StatusUnauthorized, "Invalid user ID in context", nil)
		return
	}

	user, err := h.authService.GetProfile(userID)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			utils.SendError(c, http.StatusNotFound, err.Error(), nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to fetch profile", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Profile retrieved successfully", user)
}

// GetAllUsers handles GET /api/v1/admin/users (Admin only)
func (h *AuthHandler) GetAllUsers(c *gin.Context) {
	users, err := h.authService.GetAllUsers()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "Failed to retrieve users", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "Users retrieved successfully", users)
}

// UpdateUserRole handles PATCH /api/v1/admin/users/:id/role (Admin only)
func (h *AuthHandler) UpdateUserRole(c *gin.Context) {
	idParam := c.Param("id")
	targetUserID, err := uuid.Parse(idParam)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "Invalid user ID format", nil)
		return
	}

	var req dto.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	user, err := h.authService.UpdateUserRole(targetUserID, req.Role)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			utils.SendError(c, http.StatusNotFound, err.Error(), nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "Failed to update user role", err.Error())
		return
	}

	utils.SendSuccess(c, http.StatusOK, "User role updated successfully", user)
}
