package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/JackZhao98/balloonia-server/internal/auth/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Service defines business logic for authentication
type Service interface {
	Register(ctx context.Context, in RegisterRequest) (*AuthResponse, error)
	Login(ctx context.Context, in LoginRequest) (*AuthResponse, error)
	AppleSignin(ctx context.Context, in AppleSigninRequest) (*AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error)
	DeleteAccount(ctx context.Context, userID string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, req ResetPasswordRequest) error
	GetProfile(ctx context.Context, userID string) (*ProfileResponse, error)
	UpdateProfile(ctx context.Context, userID string, req *ProfileUpdateRequest) (*ProfileResponse, error)
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
	// 检查邮箱是否已被使用
	_, err := s.repo.FindByEmail(ctx, in.Email)
	if err == nil {
		return nil, errors.New("email already registered")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		fmt.Println("err", err)
		return nil, err
	}

	// 创建密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 创建新的账户
	account, err := s.repo.CreateAccount(ctx, in.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to create account: %w", err)
	}

	// 创建凭证
	cred := &Credentials{
		Email:        in.Email,
		PasswordHash: string(hash),
		UserID:       account.ID,
		Provider:     "email",
		ProviderID:   in.Email,
	}
	if err := s.repo.CreateCredentials(ctx, cred); err != nil {
		return nil, err
	}

	// 处理 refresh tokens
	if in.ClientID != "" {
		// 如果提供了 client_id，只撤销该客户端的旧 tokens
		_ = s.repo.RevokeClientTokens(ctx, account.ID, in.ClientID)
	} else {
		// 如果没有提供 client_id，撤销所有 tokens（更安全的做法）
		_ = s.repo.RevokeAllUserTokens(ctx, account.ID)
	}

	// 生成令牌
	accessToken, err := s.jwtService.GenerateAccessToken(account.ID.String())
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateRefreshToken(account.ID.String())
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID:   account.ID,
		Token:    refreshToken,
		ClientID: in.ClientID,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       account.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) Login(ctx context.Context, in LoginRequest) (*AuthResponse, error) {
	cred, err := s.repo.FindByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}

	// 检查是否是邮箱密码登录的凭证
	if cred.Provider != "email" || cred.PasswordHash == "" || cred.Email == "" {
		return nil, errors.New("invalid login method")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(in.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// 检查账户是否已被删除
	account, err := s.repo.FindAccountByID(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}
	if account.DeletedAt != nil {
		return nil, errors.New("account has been deleted")
	}

	// 处理 refresh tokens
	if in.ClientID != "" {
		// 如果提供了 client_id，只撤销该客户端的旧 tokens
		_ = s.repo.RevokeClientTokens(ctx, cred.UserID, in.ClientID)
	} else {
		// 如果没有提供 client_id，撤销所有 tokens（更安全的做法）
		_ = s.repo.RevokeAllUserTokens(ctx, cred.UserID)
	}

	// 生成令牌
	accessToken, err := s.jwtService.GenerateAccessToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateRefreshToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID:   cred.UserID,
		Token:    refreshToken,
		ClientID: in.ClientID,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       cred.UserID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *service) AppleSignin(ctx context.Context, in AppleSigninRequest) (*AuthResponse, error) {
	// 查找是否已存在该 Apple 用户的凭证
	cred, err := s.repo.FindByProviderID(ctx, "apple", in.AppleUserID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if cred == nil {
		// 如果不存在，先创建新账户
		account, err := s.repo.CreateAccount(ctx, in.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to create account: %w", err)
		}

		// 然后创建凭证
		providerData := map[string]interface{}{
			"first_name": in.FirstName,
			"last_name":  in.LastName,
		}
		for k, v := range in.ExtraData {
			providerData[k] = v
		}

		providerDataJSON, err := json.Marshal(providerData)
		if err != nil {
			return nil, err
		}

		cred = &Credentials{
			UserID:       account.ID,
			Email:        in.Email,
			Provider:     "apple",
			ProviderID:   in.AppleUserID,
			ProviderData: providerDataJSON,
		}
		if err := s.repo.CreateCredentials(ctx, cred); err != nil {
			return nil, err
		}
	} else {
		// 检查账户是否已被删除
		account, err := s.repo.FindAccountByID(ctx, cred.UserID)
		if err != nil {
			return nil, err
		}
		if !account.DeletedAt.IsZero() {
			return nil, errors.New("account has been deleted")
		}
	}

	// 处理 refresh tokens
	if in.ClientID != "" {
		// 如果提供了 client_id，只撤销该客户端的旧 tokens
		_ = s.repo.RevokeClientTokens(ctx, cred.UserID, in.ClientID)
	} else {
		// 如果没有提供 client_id，撤销所有 tokens（更安全的做法）
		_ = s.repo.RevokeAllUserTokens(ctx, cred.UserID)
	}

	// 生成新的 tokens
	accessToken, err := s.jwtService.GenerateAccessToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtService.GenerateRefreshToken(cred.UserID.String())
	if err != nil {
		return nil, err
	}

	// 保存新的 refresh token
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID:   cred.UserID,
		Token:    refreshToken,
		ClientID: in.ClientID,
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
	token, err := s.repo.FindRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}
	if token.Revoked {
		return nil, errors.New("token has been revoked")
	}

	claims, err := s.jwtService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// 生成新的 tokens
	accessToken, err := s.jwtService.GenerateAccessToken(claims.Subject)
	if err != nil {
		return nil, err
	}
	newRefreshToken, err := s.jwtService.GenerateRefreshToken(claims.Subject)
	if err != nil {
		return nil, err
	}

	// 将旧的 token 标记为已撤销
	if err := s.repo.RevokeRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// 创建新的 refresh token，保持相同的 client ID
	userUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}
	if err := s.repo.CreateRefreshToken(ctx, &RefreshToken{
		UserID:   userUUID,
		Token:    newRefreshToken,
		ClientID: token.ClientID,
	}); err != nil {
		return nil, err
	}

	return &AuthResponse{
		UserID:       claims.Subject,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *service) DeleteAccount(ctx context.Context, userID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// 使用事务处理所有删除操作
	return s.repo.Transaction(ctx, func(txRepo Repository) error {
		// 1. 撤销所有 refresh tokens
		if err := txRepo.RevokeAllUserTokens(ctx, userUUID); err != nil {
			return fmt.Errorf("failed to revoke user tokens: %w", err)
		}

		// 2. 修改凭证表中的唯一字段
		if err := txRepo.UpdateCredentialsOnAccountDeletion(ctx, userUUID); err != nil {
			return fmt.Errorf("failed to update credentials: %w", err)
		}

		// 3. 软删除账户（profile 会通过 ON DELETE CASCADE 自动删除）
		if err := txRepo.DeleteAccount(ctx, userUUID); err != nil {
			return fmt.Errorf("failed to delete account: %w", err)
		}

		return nil
	})
}

// RequestPasswordReset initiates the password reset process
func (s *service) RequestPasswordReset(ctx context.Context, email string) error {
	// 1. 查找用户
	account, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// 2. 生成重置令牌
	token := &PasswordResetToken{
		ID:        uuid.New(),
		UserID:    account.ID,
		Token:     generateSecureToken(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	// 3. 保存令牌
	if err := s.repo.CreatePasswordResetToken(ctx, token); err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	// 4. 发送重置邮件
	// TODO: 实现邮件发送功能
	log.Printf("Password reset token for user %s: %s", email, token.Token)

	return nil
}

// ResetPassword resets the user's password using a valid token
func (s *service) ResetPassword(ctx context.Context, req ResetPasswordRequest) error {
	// 1. 验证令牌
	token, err := s.repo.GetPasswordResetToken(ctx, req.Token)
	if err != nil {
		return fmt.Errorf("invalid or expired token")
	}

	// 2. 更新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.repo.UpdateUserPassword(ctx, token.UserID, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// 3. 标记令牌为已使用
	if err := s.repo.MarkPasswordResetTokenAsUsed(ctx, token.ID); err != nil {
		log.Printf("Failed to mark token as used: %v", err)
	}

	// 4. 撤销所有现有的刷新令牌
	if err := s.repo.DeleteAllUserTokens(ctx, token.UserID); err != nil {
		log.Printf("Failed to revoke refresh tokens: %v", err)
	}

	return nil
}

// generateSecureToken generates a secure random token
func generateSecureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return base64.URLEncoding.EncodeToString(b)
}

// GetProfile retrieves a user's profile
func (s *service) GetProfile(ctx context.Context, userID string) (*ProfileResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// 获取账户信息
	account, err := s.repo.FindAccountByID(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	// 获取 profile 信息
	profile, err := s.repo.GetProfile(ctx, userUUID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 如果 profile 不存在，返回只包含基本信息的响应
	response := &ProfileResponse{
		UserID: account.ID.String(),
		Email:  account.Email,
	}

	// 如果 profile 存在，添加 profile 信息
	if profile != nil {
		response.Nickname = profile.Nickname
		response.AvatarURL = profile.AvatarURL
		response.Bio = profile.Bio
	}

	return response, nil
}

// UpdateProfile updates a user's profile
func (s *service) UpdateProfile(ctx context.Context, userID string, req *ProfileUpdateRequest) (*ProfileResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// 检查用户是否存在
	account, err := s.repo.FindAccountByID(ctx, userUUID)
	if err != nil {
		return nil, err
	}

	// 获取现有的 profile 或创建新的
	profile, err := s.repo.GetProfile(ctx, userUUID)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		// 如果 profile 不存在，创建新的
		profile = &Profile{
			UserID: userUUID,
		}
	}

	// 更新字段（只更新非空字段）
	updates := make(map[string]interface{})
	if req.Nickname != nil {
		profile.Nickname = *req.Nickname
		updates["nickname"] = *req.Nickname
	}
	if req.AvatarURL != nil {
		profile.AvatarURL = *req.AvatarURL
		updates["avatar_url"] = *req.AvatarURL
	}
	if req.Bio != nil {
		profile.Bio = *req.Bio
		updates["bio"] = *req.Bio
	}

	// 如果是新 profile，创建它
	if profile.CreatedAt.IsZero() {
		err = s.repo.CreateProfile(ctx, profile)
	} else {
		// 否则更新现有的
		err = s.repo.UpdateProfile(ctx, userUUID, updates)
	}
	if err != nil {
		return nil, err
	}

	// 返回更新后的完整 profile
	return &ProfileResponse{
		UserID:    account.ID.String(),
		Email:     account.Email,
		Nickname:  profile.Nickname,
		AvatarURL: profile.AvatarURL,
		Bio:       profile.Bio,
	}, nil
}
