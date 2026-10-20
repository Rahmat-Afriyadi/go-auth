package services

import (
	"errors"
	"strings"
	"time"

	"gin-auth/internal/dto"
	"gin-auth/internal/models"
	"gin-auth/internal/repositories"
	"gin-auth/internal/utils"

	"github.com/google/uuid"
)

var (
	ErrEmailAlreadyExists = errors.New("email is already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountDeactivated = errors.New("account is deactivated")
	ErrInvalidRefresh     = errors.New("invalid or expired refresh token")
	ErrUserNotFound       = errors.New("user not found")
)

type AuthService interface {
	Register(req dto.RegisterRequest) (*dto.AuthResponse, error)
	Login(req dto.LoginRequest) (*dto.AuthResponse, error)
	RefreshToken(req dto.RefreshTokenRequest) (*dto.TokenPairResponse, error)
	Logout(refreshToken string) error
	GetProfile(userID uuid.UUID) (*dto.UserResponse, error)
	GetAllUsers() ([]dto.UserResponse, error)
	UpdateUserRole(userID uuid.UUID, role models.Role) (*dto.UserResponse, error)
}

type authService struct {
	userRepo   repositories.UserRepository
	jwtManager *utils.JWTManager
}

func NewAuthService(userRepo repositories.UserRepository, jwtManager *utils.JWTManager) AuthService {
	return &authService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
	}
}

func (s *authService) Register(req dto.RegisterRequest) (*dto.AuthResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	existing, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Name:         strings.TrimSpace(req.Name),
		Email:        email,
		PasswordHash: hashedPassword,
		Role:         models.RoleUser,
		IsActive:     true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	tokens, err := s.issueTokens(user)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		User:   dto.ToUserResponse(user),
		Tokens: *tokens,
	}, nil
}

func (s *authService) Login(req dto.LoginRequest) (*dto.AuthResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, err
	}
	if user == nil || !utils.CheckPasswordHash(req.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}
	if !user.IsActive {
		return nil, ErrAccountDeactivated
	}

	tokens, err := s.issueTokens(user)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		User:   dto.ToUserResponse(user),
		Tokens: *tokens,
	}, nil
}

func (s *authService) RefreshToken(req dto.RefreshTokenRequest) (*dto.TokenPairResponse, error) {
	if _, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken); err != nil {
		return nil, ErrInvalidRefresh
	}

	storedToken, err := s.userRepo.FindRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, err
	}
	if storedToken == nil || storedToken.Revoked || time.Now().After(storedToken.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}
	if !storedToken.User.IsActive {
		return nil, ErrAccountDeactivated
	}

	// Token rotation: revoke old refresh token and issue a new pair
	if err := s.userRepo.RevokeRefreshToken(req.RefreshToken); err != nil {
		return nil, err
	}

	return s.issueTokens(&storedToken.User)
}

func (s *authService) Logout(refreshToken string) error {
	if refreshToken == "" {
		return nil
	}
	return s.userRepo.RevokeRefreshToken(refreshToken)
}

func (s *authService) GetProfile(userID uuid.UUID) (*dto.UserResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	res := dto.ToUserResponse(user)
	return &res, nil
}

func (s *authService) GetAllUsers() ([]dto.UserResponse, error) {
	users, err := s.userRepo.FindAll()
	if err != nil {
		return nil, err
	}
	res := make([]dto.UserResponse, 0, len(users))
	for i := range users {
		res = append(res, dto.ToUserResponse(&users[i]))
	}
	return res, nil
}

func (s *authService) UpdateUserRole(userID uuid.UUID, role models.Role) (*dto.UserResponse, error) {
	user, err := s.userRepo.UpdateRole(userID, role)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	res := dto.ToUserResponse(user)
	return &res, nil
}

func (s *authService) issueTokens(user *models.User) (*dto.TokenPairResponse, error) {
	accessToken, expiresIn, err := s.jwtManager.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, expiresAt, err := s.jwtManager.GenerateRefreshToken(user)
	if err != nil {
		return nil, err
	}

	rtModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	if err := s.userRepo.SaveRefreshToken(rtModel); err != nil {
		return nil, err
	}

	return &dto.TokenPairResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}
