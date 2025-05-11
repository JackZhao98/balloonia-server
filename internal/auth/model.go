package auth

import (
	"time"

	"github.com/google/uuid"
)

// Account maps to users.account table
type Account struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;column:id"`
	Email     string     `gorm:"type:varchar(255);uniqueIndex"`
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt *time.Time `gorm:"column:deleted_at;index"`
}

// TableName overrides GORM table name
func (Account) TableName() string {
	return "users.account"
}

// Credentials maps to auth.credentials table
type Credentials struct {
	ID           int64     `gorm:"primaryKey;column:id;autoIncrement"`
	UserID       uuid.UUID `gorm:"type:uuid;column:user_id;not null"`
	Email        string    `gorm:"size:255;uniqueIndex"`
	PasswordHash string    `gorm:"type:text;not null;column:password_hash"`
	Provider     string    `gorm:"size:50;not null;default:'email'"`
	ProviderID   string    `gorm:"size:255"`
	ProviderData []byte    `gorm:"type:jsonb"`
	CreatedAt    time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

// TableName overrides GORM table name
func (Credentials) TableName() string {
	return "auth.credentials"
}

// RefreshToken maps to auth.refresh_tokens table
type RefreshToken struct {
	ID        int64     `gorm:"primaryKey;column:id;autoIncrement"`
	UserID    uuid.UUID `gorm:"type:uuid;column:user_id;index"`
	Token     string    `gorm:"type:text;uniqueIndex;not null"`
	ClientID  string    `gorm:"type:text;column:client_id;index"`
	Revoked   bool      `gorm:"default:false"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (RefreshToken) TableName() string {
	return "auth.refresh_tokens"
}

// PasswordResetToken represents a password reset token in the database
type PasswordResetToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null"`
	Token     string     `gorm:"type:text;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	UsedAt    *time.Time `gorm:"default:null"`
	CreatedAt time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

// TableName overrides GORM table name
func (PasswordResetToken) TableName() string {
	return "auth.password_reset_tokens"
}

// User represents a user in the database
type User struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey"`
	Email     string     `gorm:"size:255;uniqueIndex"`
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time  `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt *time.Time `gorm:"column:deleted_at;index"`
}

func (User) TableName() string {
	return "users.account"
}
