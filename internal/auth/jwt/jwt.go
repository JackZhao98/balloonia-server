package jwt

import (
	"errors"
	"time"

	"github.com/JackZhao98/balloonia-server/config"
	"github.com/golang-jwt/jwt/v5"
)

type Service interface {
	GenerateAccessToken(userID string) (string, error)
	GenerateRefreshToken(userID string) (string, error)
	ValidateAccessToken(token string) (*jwt.RegisteredClaims, error)
	ValidateRefreshToken(token string) (*jwt.RegisteredClaims, error)
}

type jwtService struct {
	accessSecretKey  []byte
	refreshSecretKey []byte
}

func NewService() Service {
	return &jwtService{
		accessSecretKey:  []byte(config.Get().JwtSecret),
		refreshSecretKey: []byte(config.Get().JwtRefreshTokenSecret),
	}
}

func (s *jwtService) GenerateAccessToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // 15分钟过期
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.accessSecretKey)
}

func (s *jwtService) GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)), // 7天过期
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.refreshSecretKey)
}

func (s *jwtService) ValidateAccessToken(tokenString string) (*jwt.RegisteredClaims, error) {
	return s.validateToken(tokenString, s.accessSecretKey)
}

func (s *jwtService) ValidateRefreshToken(tokenString string) (*jwt.RegisteredClaims, error) {
	return s.validateToken(tokenString, s.refreshSecretKey)
}

func (s *jwtService) validateToken(tokenString string, secretKey []byte) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
