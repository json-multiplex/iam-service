package service

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"

	"github.com/json-multiplex/iam-service/internal/models"
	"github.com/json-multiplex/iam-service/internal/store"
)

type Service struct {
	Store                 store.Store
	TokenSignKey          *rsa.PrivateKey
	TokenVerifyKey        *rsa.PublicKey
	TokenExpirationPeriod time.Duration
}

type AuthenticateRequest struct {
	Account  string
	User     string
	Password string
}

type AuthenticateResponse struct {
	Token string
}

type CreateAccountRequest struct {
	Account      models.Account
	Root         models.User
	RootPassword string
}

type GetUserRequest struct {
	Token string
	Name  string
}

type CreateUserRequest struct {
	Token string
	User  models.User
}

type CreateIdentityRequest struct {
	Token    string
	Identity models.Identity
	Parent   string
}

type claims struct {
	jwt.StandardClaims
	AuthMethod string `json:"amr"`
}

func (c *claims) Valid() error {
	return c.StandardClaims.Valid()
}

const (
	amrPassword string = "password"
)

func (s *Service) Authenticate(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error) {
	ok, err := s.Store.CheckPassword(ctx, store.CheckPasswordRequest{
		Account:  req.Account,
		User:     req.User,
		Password: req.Password,
	})

	if !ok {
		return AuthenticateResponse{}, errors.New("failed to authenticate")
	}

	// token := jwt.NewWithClaims(jwt.SigningMethodRS256, &jwt.MapClaims{
	// 	"sub": req.User,
	// 	"aud": req.Account,
	// 	"exp": time.Now().Add(s.TokenExpirationPeriod).Unix(),
	// 	"iat": time.Now().Unix(),
	// 	"amr": "password",
	// })

	accountSegments := strings.Split(req.Account, "/")
	accountID := accountSegments[1]

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims{
		AuthMethod: amrPassword,
		StandardClaims: jwt.StandardClaims{
			Subject:   req.User,
			Audience:  accountID,
			ExpiresAt: time.Now().Add(s.TokenExpirationPeriod).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})

	tokenString, err := token.SignedString(s.TokenSignKey)
	if err != nil {
		return AuthenticateResponse{}, errors.Wrap(err, "error signing token")
	}

	return AuthenticateResponse{Token: tokenString}, err
}

func (s *Service) CreateAccount(ctx context.Context, req CreateAccountRequest) (models.Account, error) {
	return s.Store.CreateAccount(ctx, store.CreateAccountRequest{
		Account:      req.Account,
		Root:         req.Root,
		RootPassword: req.RootPassword,
	})
}

func (s *Service) GetUser(ctx context.Context, req GetUserRequest) (models.User, error) {
	claims, err := s.parseToken(req.Token)
	if err != nil {
		return models.User{}, err
	}

	return s.Store.GetUser(ctx, store.GetUserRequest{
		AccountID: claims.Audience,
		Name:      req.Name,
	})
}

func (s *Service) CreateUser(ctx context.Context, req CreateUserRequest) (models.User, error) {
	return s.Store.CreateUser(ctx, store.CreateUserRequest{
		AccountID: uuid.NewV4().String(),
		User:      req.User,
	})
}

func (s *Service) CreateIdentity(ctx context.Context, req CreateIdentityRequest) (models.Identity, error) {
	return s.Store.CreateIdentity(ctx, store.CreateIdentityRequest{
		Identity: req.Identity,
		Parent:   req.Parent,
	})
}

func (s *Service) parseToken(token string) (*claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected token signing method: %v", token.Header["alg"])
		}

		return s.TokenVerifyKey, nil
	})

	return parsed.Claims.(*claims), err
}
