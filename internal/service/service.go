package service

import (
	"context"
	"fmt"
	"time"

	uuid "github.com/satori/go.uuid"
)

type Service struct{}

type User struct {
	Name       string
	CreateTime time.Time
	UpdateTime time.Time
	DeleteTime time.Time

	IsRoot      bool
	DisplayName string
}

type Identity struct {
	Name       string
	CreateTime time.Time
	UpdateTime time.Time
	DeleteTime time.Time

	AuthMethod AuthMethod
	Password   string
}

type AuthMethod int

const (
	AuthMethodPassword AuthMethod = 1
)

type CreateUserRequest struct {
	Token string
	User  User
}

type CreateIdentityRequest struct {
	Token    string
	Identity Identity
	Parent   string
}

func (s *Service) CreateUser(ctx context.Context, req CreateUserRequest) (User, error) {
	return User{
		Name:        fmt.Sprintf("users/%s", uuid.NewV4()),
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
		DeleteTime:  time.Now(),
		IsRoot:      true,
		DisplayName: req.User.DisplayName,
	}, nil
}

func (s *Service) CreateIdentity(ctx context.Context, req CreateIdentityRequest) (Identity, error) {
	return Identity{
		Name:       fmt.Sprintf("%s/identities/%s", req.Parent, uuid.NewV4()),
		CreateTime: time.Now(),
		UpdateTime: time.Now(),
		DeleteTime: time.Now(),
		AuthMethod: req.Identity.AuthMethod,
		Password:   "",
	}, nil
}
