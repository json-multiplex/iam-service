package store

import (
	"context"

	"github.com/json-multiplex/iam-service/internal/models"
)

type CheckPasswordRequest struct {
	Account  string
	User     string
	Password string
}

type CreateAccountRequest struct {
	Account      models.Account
	Root         models.User
	RootPassword string
}

type GetUserRequest struct {
	AccountID string
	Name      string
}

type CreateUserRequest struct {
	AccountID string
	User      models.User
}

type CreateIdentityRequest struct {
	AccountID string
	Identity  models.Identity
	Parent    string
}

type Store interface {
	CheckPassword(context.Context, CheckPasswordRequest) (bool, error)
	CreateAccount(context.Context, CreateAccountRequest) (models.Account, error)
	GetUser(context.Context, GetUserRequest) (models.User, error)
	CreateUser(context.Context, CreateUserRequest) (models.User, error)
	CreateIdentity(context.Context, CreateIdentityRequest) (models.Identity, error)
}
