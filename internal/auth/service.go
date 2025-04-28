package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/JackZhao98/balloonia-server/internal/auth/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service defines business logic for authentication
type Service interface {
	Register(ctx context.Context, in RegisterRequest) (*AuthResponse, error)
	Login(ctx context.Context, in LoginRequest) (*AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)
}

type service struct {
	repo       Repository
	jwtService jwt.Service
}

// NewService creates a new Auth Service
func NewService(r Repository, jwtService jwt.Service) Service {
	return &service{
		repo:       r,
		jwtService: jwtService,
	}
}

func (s *service) Register(ctx context.Context, in RegisterRequest) (*AuthResponse, error) {
	_, err := s.repo.FindByEmail(ctx, in.Email)
	if err == nil {
		return nil, errors.New("email already registered")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		fmt.Println("err", err)
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	cred := &Credentials{
		Email:        in.Email,
		PasswordHash: string(hash),
		UserID:       uuid.New(),
	}
	if err := s.repo.CreateCredentials(ctx, cred); err != nil {
		return nil, err
	}

	// 先物理删除该用户所有refresh token
	_ = s.repo.DeleteAllUserTokens(ctx, cred.UserID.String())

	accessToken, err := s.jwtService.GenerateAccessToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateRefreshToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID: cred.UserID,
		Token:  refreshToken,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       cred.UserID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) Login(ctx context.Context, in LoginRequest) (*AuthResponse, error) {
	cred, err := s.repo.FindByEmail(ctx, in.Email)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(in.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// 先物理删除该用户所有refresh token
	_ = s.repo.DeleteAllUserTokens(ctx, cred.UserID.String())

	accessToken, err := s.jwtService.GenerateAccessToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateRefreshToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID: cred.UserID,
		Token:  refreshToken,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       cred.UserID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// 查找并校验 refresh token 是否有效且未撤销
	_, err := s.repo.FindRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}
	claims, err := s.jwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	accessToken, err := s.jwtService.GenerateAccessToken(claims.Subject)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := s.jwtService.GenerateRefreshToken(claims.Subject)
	if err != nil {
		return nil, err
	}
	// 先物理删除该用户所有refresh token
	userUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}
	_ = s.repo.DeleteAllUserTokens(ctx, userUUID.String())
	// 存储新的 refresh token
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID: userUUID,
		Token:  newRefreshToken,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       claims.Subject,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}
