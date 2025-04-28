package auth

import (
	"time"

	"github.com/google/uuid"
)

// Credentials maps to auth.credentials table
type Credentials struct {
	ID           uint      `gorm:"primaryKey;column:id"`
	UserID       uuid.UUID `gorm:"type:uuid;column:user_id;uniqueIndex"`
	Email        string    `gorm:"size:255;not null;uniqueIndex"`
	PasswordHash string    `gorm:"type:text;not null;column:password_hash"`
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
	Revoked   bool      `gorm:"default:false"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (RefreshToken) TableName() string {
	return "auth.refresh_tokens"
}
