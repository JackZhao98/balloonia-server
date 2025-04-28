package auth

import (
	"context"

	"gorm.io/gorm"
)

// Repository defines DB operations for credentials
type Repository interface {
	CreateCredentials(ctx context.Context, cred *Credentials) error
	FindByEmail(ctx context.Context, email string) (*Credentials, error)
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
