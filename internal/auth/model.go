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
