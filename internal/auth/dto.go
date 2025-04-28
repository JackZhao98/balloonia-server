package auth

// RegisterRequest is the payload for user registration
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Username string `json:"username" binding:"required,alphanumunicode,min=3,max=30"`
}

// LoginRequest is the payload for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// AuthResponse is returned after successful auth actions
type AuthResponse struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}
