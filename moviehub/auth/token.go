package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	MemberID int64  `json:"memberId"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type Issuer struct {
	Secret []byte
	TTL    time.Duration
}

func (i *Issuer) Issue(memberID int64, role string) (string, error) {
	if len(i.Secret) < 32 {
		return "", errors.New("JWT secret must be at least 32 bytes")
	}

	now := time.Now()
	claims := Claims{
		MemberID: memberID,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.TTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(i.Secret)
}

func (i *Issuer) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return i.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
