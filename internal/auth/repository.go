package auth

import (
	"context"

	"gorm.io/gorm"
)

// Repository defines DB operations for credentials
type Repository interface {
	CreateCredentials(ctx context.Context, cred *Credentials) error
	FindByEmail(ctx context.Context, email string) (*Credentials, error)

	// refresh token 相关
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	FindRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	DeleteAllUserTokens(ctx context.Context, userID string) error
}

type repository struct {
	db *gorm.DB
}

// NewRepository returns a new Auth Repository
func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

func (r *repository) CreateCredentials(ctx context.Context, cred *Credentials) error {
	return r.db.WithContext(ctx).Create(cred).Error
}

func (r *repository) FindByEmail(ctx context.Context, email string) (*Credentials, error) {
	var cred Credentials
	err := r.db.WithContext(ctx).
		Where("email = ?", email).
		First(&cred).Error
	return &cred, err
}

func (r *repository) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *repository) FindRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var refreshToken RefreshToken
	err := r.db.WithContext(ctx).
		Where("token = ? AND revoked = false", token).
		First(&refreshToken).Error
	return &refreshToken, err
}

func (r *repository) RevokeRefreshToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("token = ?", token).Update("revoked", true).Error
}

func (r *repository) RevokeAllUserTokens(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

func (r *repository) DeleteAllUserTokens(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&RefreshToken{}).Error
}
