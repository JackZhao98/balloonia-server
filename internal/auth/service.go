package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/JackZhao98/balloonia-server/config"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service defines business logic for authentication
type Service interface {
	Register(ctx context.Context, in RegisterRequest) (*AuthResponse, error)
	Login(ctx context.Context, in LoginRequest) (*AuthResponse, error)
}

type service struct {
	repo Repository
}

// NewService creates a new Auth Service
func NewService(r Repository) Service {
	return &service{repo: r}
}
func (s *service) Register(ctx context.Context, in RegisterRequest) (*AuthResponse, error) {
	// 先尝试查找邮箱是否已存在
	_, err := s.repo.FindByEmail(ctx, in.Email)
	if err == nil {
		return nil, errors.New("email already registered")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		fmt.Println("err", err)
		return nil, err
	}

	// 生成密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 构造模型并写入
	cred := &Credentials{
		Email:        in.Email,
		PasswordHash: string(hash),
		UserID:       uuid.New(),
	}
	if err := s.repo.CreateCredentials(ctx, cred); err != nil {
		return nil, err
	}

	// 生成并返回 JWT（替换下面这行）
	token := config.Get().JwtSecret
	return &AuthResponse{UserID: cred.UserID.String(), Token: token}, nil
}
func (s *service) Login(ctx context.Context, in LoginRequest) (*AuthResponse, error) {
	cred, err := s.repo.FindByEmail(ctx, in.Email)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(in.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	token := "..." // generate JWT
	return &AuthResponse{UserID: cred.UserID.String(), Token: token}, nil
}
