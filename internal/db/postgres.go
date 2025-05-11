package db

import (
	"fmt"
	"log"

	"github.com/JackZhao98/balloonia-server/config"
	"github.com/JackZhao98/balloonia-server/internal/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase() {
	dsn := config.Get().PostgresDSN
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// 自动迁移所有表
	if err := db.AutoMigrate(
		&auth.Account{},
		&auth.Credentials{},
		&auth.RefreshToken{},
		&auth.PasswordResetToken{},
		&auth.User{},
	); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// 添加外键约束
	if err := db.Exec(`
		DO $$ 
		BEGIN
			-- 确保 auth schema 存在
			IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') THEN
				CREATE SCHEMA auth;
			END IF;

			-- 确保 users schema 存在
			IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'users') THEN
				CREATE SCHEMA users;
			END IF;

			-- auth.credentials 表的外键约束
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.table_constraints 
				WHERE constraint_name = 'fk_credentials_user_id'
			) THEN
				ALTER TABLE auth.credentials
				ADD CONSTRAINT fk_credentials_user_id
				FOREIGN KEY (user_id) REFERENCES users.account(id)
				ON DELETE CASCADE;
			END IF;

			-- auth.refresh_tokens 表的外键约束
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.table_constraints 
				WHERE constraint_name = 'fk_refresh_tokens_user_id'
			) THEN
				ALTER TABLE auth.refresh_tokens
				ADD CONSTRAINT fk_refresh_tokens_user_id
				FOREIGN KEY (user_id) REFERENCES users.account(id)
				ON DELETE CASCADE;
			END IF;

			-- auth.password_reset_tokens 表的外键约束
			IF NOT EXISTS (
				SELECT 1 FROM information_schema.table_constraints 
				WHERE constraint_name = 'fk_password_reset_tokens_user_id'
			) THEN
				ALTER TABLE auth.password_reset_tokens
				ADD CONSTRAINT fk_password_reset_tokens_user_id
				FOREIGN KEY (user_id) REFERENCES users.account(id)
				ON DELETE CASCADE;
			END IF;
		END $$;
	`).Error; err != nil {
		log.Printf("Warning: Failed to add foreign key constraints: %v", err)
	}

	DB = db
	fmt.Println("Successfully connected to database")
}
