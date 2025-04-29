package auth

import (
	"time"

	"github.com/google/uuid"
)

// Account maps to users.account table
type Account struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;column:id"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime"`
	DeletedAt time.Time `gorm:"column:deleted_at;index"`
}

// TableName overrides GORM table name
func (Account) TableName() string {
	return "users.account"
}

// Credentials maps to auth.credentials table
type Credentials struct {
	ID           uint      `gorm:"primaryKey;column:id"`
	UserID       uuid.UUID `gorm:"type:uuid;column:user_id;uniqueIndex"`
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
	ID        string     `db:"id"`
	UserID    string     `db:"user_id"`
	Token     string     `db:"token"`
	ExpiresAt time.Time  `db:"expires_at"`
	UsedAt    *time.Time `db:"used_at"`
	CreatedAt time.Time  `db:"created_at"`
}

// User represents a user in the database
type User struct {
	ID        string     `db:"id"`
	Email     string     `db:"email"`
	Password  string     `db:"password"`
	CreatedAt time.Time  `db:"created_at"`
	UpdatedAt time.Time  `db:"updated_at"`
	DeletedAt *time.Time `db:"deleted_at"`
}

func (User) TableName() string {
	return "users.account"
}
