package auth

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email" example:"test@example.com"`
	Password string `json:"password" binding:"required,min=8" example:"password123"`
	ClientID string `json:"client_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"test@example.com"`
	Password string `json:"password" binding:"required" example:"password123"`
	ClientID string `json:"client_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// AppleSigninRequest represents the request body for Apple Sign In
type AppleSigninRequest struct {
	AppleUserID string         `json:"apple_user_id" binding:"required" example:"001234.abcd1234.1234"`
	Email       string         `json:"email" example:"user@example.com"`
	FirstName   string         `json:"first_name,omitempty" example:"John"`
	LastName    string         `json:"last_name,omitempty" example:"Doe"`
	ExtraData   map[string]any `json:"extra_data,omitempty"`
	ClientID    string         `json:"client_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// RefreshTokenRequest represents the request body for token refresh
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// AuthResponse represents the response body for authentication operations
type AuthResponse struct {
	UserID       string `json:"user_id" example:"123e4567-e89b-12d3-a456-426614174000"`
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`
}

// TokenResponse represents the response for authentication operations
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	ExpiresIn    int64  `json:"expires_in" example:"3600"`
}

// RequestPasswordResetRequest represents the request to initiate password reset
type RequestPasswordResetRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
}

// ResetPasswordRequest represents the request to reset password with token
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required" example:"abc123def456..."`
	NewPassword string `json:"new_password" binding:"required,min=8" example:"newpassword123"`
}
