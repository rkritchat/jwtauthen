package jwtauthen

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	login               = "login"
	register            = "register"
	ping                = "ping"
	headerAuthorization = "Authorization"
	empty               = ""
)

var invalidClaim = errors.New("invalid claims")
var tokenIsExpired = errors.New("token is expired")

type JwtAuthen interface {
	Authentication(next http.Handler) http.Handler
}

type jwtAuthen struct {
	accessToken string
}

func NewJwtAuthen(accessToken string) JwtAuthen {
	return &jwtAuthen{
		accessToken: accessToken,
	}
}

type claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

func (c claims) Valid() error {
	//validate username
	if len(c.Email) == 0 {
		return invalidClaim
	}

	if time.Now().After(c.ExpiresAt.Time) {
		log.Println("token is expired")
		return tokenIsExpired
	}
	return nil
}

func (j jwtAuthen) Authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requiredCheck(r.URL.Path) {
			ctx, err := j.isTokenValid(r)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (j jwtAuthen) isTokenValid(r *http.Request) (context.Context, error) {
	//validate token
	claim, err := j.validateToken(r)
	if err != nil {
		return nil, err
	}
	emailCtx := context.WithValue(r.Context(), "email", claim.Email)
	return context.WithValue(emailCtx, "role", claim.Role), nil
}

func (j jwtAuthen) validateToken(r *http.Request) (claims, error) {
	token := extractToken(r)
	var c claims
	tkn, err := jwt.ParseWithClaims(token, &c, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.accessToken), nil
	})
	if err != nil {
		log.Printf("[%v]jwt.ParseWithClaims: %v", token, err)
		return c, err
	}
	if !tkn.Valid {
		log.Printf("[%v] is invalid: %v", token, err)
		return c, err
	}
	return c, nil
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get(headerAuthorization)
	token := strings.Split(auth, " ")
	if len(token) != 2 {
		return empty
	}
	return token[1]
}

func requiredCheck(url string) bool {
	return !strings.Contains(strings.ToLower(url), login) &&
		!strings.Contains(strings.ToLower(url), register) &&
		!strings.Contains(strings.ToLower(url), ping)
}
