package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Repository defines DB operations for credentials
type Repository interface {
	// 事务支持
	WithTx(tx *gorm.DB) Repository
	Transaction(ctx context.Context, fn func(txRepo Repository) error) error

	// Account 相关
	CreateAccount(ctx context.Context, email string) (*Account, error)
	DeleteAccount(ctx context.Context, userID uuid.UUID) error
	FindAccountByID(ctx context.Context, userID uuid.UUID) (*Account, error)

	// Credentials 相关
	CreateCredentials(ctx context.Context, cred *Credentials) error
	FindByEmail(ctx context.Context, email string) (*Credentials, error)
	FindByProviderID(ctx context.Context, provider, providerID string) (*Credentials, error)
	UpdateCredentialsOnAccountDeletion(ctx context.Context, userID uuid.UUID) error

	// Profile 相关
	CreateProfile(ctx context.Context, profile *Profile) error
	GetProfile(ctx context.Context, userID uuid.UUID) (*Profile, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error
	DeleteProfile(ctx context.Context, userID uuid.UUID) error

	// refresh token 相关
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	FindRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error
	DeleteAllUserTokens(ctx context.Context, userID uuid.UUID) error
	RevokeClientTokens(ctx context.Context, userID uuid.UUID, clientID string) error

	// Password reset methods
	CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error
	DeleteExpiredPasswordResetTokens(ctx context.Context) error

	// User methods
	GetUserByEmail(ctx context.Context, email string) (*Account, error)
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
}

type repository struct {
	db *gorm.DB
}

// NewRepository returns a new Auth Repository
func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

func (r *repository) WithTx(tx *gorm.DB) Repository {
	return &repository{db: tx}
}

func (r *repository) Transaction(ctx context.Context, fn func(txRepo Repository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(r.WithTx(tx))
	})
}

func (r *repository) CreateAccount(ctx context.Context, email string) (*Account, error) {
	account := &Account{
		ID:    uuid.New(),
		Email: email,
	}
	err := r.db.WithContext(ctx).Create(account).Error
	return account, err
}

func (r *repository) CreateCredentials(ctx context.Context, cred *Credentials) error {
	return r.db.WithContext(ctx).Create(cred).Error
}

func (r *repository) FindByEmail(ctx context.Context, email string) (*Credentials, error) {
	var cred Credentials
	err := r.db.WithContext(ctx).
		Table("auth.credentials").
		Where("email = ? AND provider = 'email'", email).
		First(&cred).Error
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func (r *repository) FindByProviderID(ctx context.Context, provider, providerID string) (*Credentials, error) {
	var cred Credentials
	err := r.db.WithContext(ctx).
		Joins("JOIN users.account ON auth.credentials.user_id = users.account.id").
		Where("auth.credentials.provider = ? AND auth.credentials.provider_id = ? AND users.account.deleted_at IS NULL", provider, providerID).
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

func (r *repository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error
}

func (r *repository) DeleteAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&RefreshToken{}).Error
}

func (r *repository) RevokeClientTokens(ctx context.Context, userID uuid.UUID, clientID string) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("user_id = ? AND client_id = ?", userID, clientID).Update("revoked", true).Error
}

func (r *repository) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&Account{}).
		Where("id = ?", userID).
		Update("deleted_at", &now).
		Error
}

func (r *repository) FindAccountByID(ctx context.Context, userID uuid.UUID) (*Account, error) {
	var account Account
	err := r.db.WithContext(ctx).
		Where("id = ?", userID).
		First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *repository) UpdateCredentialsOnAccountDeletion(ctx context.Context, userID uuid.UUID) error {
	// 查找用户的所有凭证
	var creds []Credentials
	if err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&creds).Error; err != nil {
		return err
	}

	// 开启事务
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, cred := range creds {
			// 对于每个凭证，修改其唯一标识字段
			updates := map[string]interface{}{
				"email":       fmt.Sprintf("deleted_%s_%s", cred.Email, userID),
				"provider_id": fmt.Sprintf("deleted_%s_%s", cred.ProviderID, userID),
			}

			if err := tx.Model(&Credentials{}).
				Where("id = ?", cred.ID).
				Updates(updates).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// CreatePasswordResetToken creates a new password reset token
func (r *repository) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// GetPasswordResetToken retrieves a password reset token by token string
func (r *repository) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	var result PasswordResetToken
	err := r.db.WithContext(ctx).
		Where("token = ? AND used_at IS NULL AND expires_at > NOW()", token).
		First(&result).Error
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// MarkPasswordResetTokenAsUsed marks a password reset token as used
func (r *repository) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Model(&PasswordResetToken{}).
		Where("id = ?", tokenID).
		Update("used_at", time.Now()).
		Error
}

// DeleteExpiredPasswordResetTokens deletes all expired password reset tokens
func (r *repository) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < NOW()").
		Delete(&PasswordResetToken{}).
		Error
}

// GetUserByEmail retrieves a user by email
func (r *repository) GetUserByEmail(ctx context.Context, email string) (*Account, error) {
	var account Account
	err := r.db.WithContext(ctx).
		Table("users.account").
		Where("email = ? AND deleted_at IS NULL", email).
		First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// UpdateUserPassword updates a user's password
func (r *repository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	return r.db.WithContext(ctx).
		Table("auth.credentials").
		Where("user_id = ? AND provider = 'email'", userID).
		Update("password_hash", hashedPassword).
		Error
}

// CreateProfile creates a new profile
func (r *repository) CreateProfile(ctx context.Context, profile *Profile) error {
	return r.db.WithContext(ctx).Create(profile).Error
}

// GetProfile retrieves a profile by user ID
func (r *repository) GetProfile(ctx context.Context, userID uuid.UUID) (*Profile, error) {
	var profile Profile
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		First(&profile).Error
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

// UpdateProfile updates a profile
func (r *repository) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error {
	return r.db.WithContext(ctx).
		Model(&Profile{}).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Updates(updates).Error
}

// DeleteProfile soft deletes a profile
func (r *repository) DeleteProfile(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&Profile{}).
		Where("user_id = ?", userID).
		Update("deleted_at", &now).Error
}
