package main

import (
	"context"
	"strings"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/json-multiplex/iam-service/generated/v0"
	"github.com/json-multiplex/iam-service/internal/models"
	"github.com/json-multiplex/iam-service/internal/service"
	"github.com/pkg/errors"
	"google.golang.org/grpc/metadata"
)

type server struct {
	Service service.Service
}

func (s *server) Authenticate(ctx context.Context, req *pb.AuthenticateRequest) (*pb.AuthenticateResponse, error) {
	res, err := s.Service.Authenticate(ctx, service.AuthenticateRequest{
		Account:  req.Account,
		User:     req.User,
		Password: req.Password,
	})

	if err != nil {
		return nil, err
	}

	return &pb.AuthenticateResponse{
		Token: res.Token,
	}, nil
}

func (s *server) GetAccount(ctx context.Context, req *pb.GetAccountRequest) (*pb.Account, error) {
	return nil, nil
}

func (s *server) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.Account, error) {
	inAccount := deserializeAccount(req.Account)
	inUser := deserializeUser(req.Root)

	outAccount, err := s.Service.CreateAccount(ctx, service.CreateAccountRequest{
		Account:      inAccount,
		Root:         inUser,
		RootPassword: req.RootPassword,
	})

	if err != nil {
		return nil, err
	}

	return serializeAccount(outAccount)
}

func (s *server) UpdateAccount(ctx context.Context, req *pb.UpdateAccountRequest) (*pb.Account, error) {
	return nil, nil
}

func (s *server) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*empty.Empty, error) {
	return nil, nil
}

func (s *server) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return nil, nil
}

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	resultUser, err := s.Service.GetUser(ctx, service.GetUserRequest{
		Token: getToken(ctx),
		Name:  req.Name,
	})

	if err != nil {
		return nil, err
	}

	outUser, err := serializeUser(resultUser)
	if err != nil {
		return nil, err
	}

	return outUser, nil
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	inUser := deserializeUser(req.User)

	resultUser, err := s.Service.CreateUser(ctx, service.CreateUserRequest{
		Token: getToken(ctx),
		User:  inUser,
	})

	if err != nil {
		return nil, err
	}

	outUser, err := serializeUser(resultUser)
	if err != nil {
		return nil, err
	}

	return outUser, nil
}

func (s *server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.User, error) {
	return nil, nil
}

func (s *server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*empty.Empty, error) {
	return nil, nil
}

func (s *server) ListIdentities(ctx context.Context, req *pb.ListIdentitiesRequest) (*pb.ListIdentitiesResponse, error) {
	return nil, nil
}

func (s *server) GetIdentity(ctx context.Context, req *pb.GetIdentityRequest) (*pb.Identity, error) {
	return nil, nil
}

func (s *server) CreateIdentity(ctx context.Context, req *pb.CreateIdentityRequest) (*pb.Identity, error) {
	inIdentity, err := deserializeIdentity(req.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "error deserializing identity")
	}

	resultIdentity, err := s.Service.CreateIdentity(ctx, service.CreateIdentityRequest{
		Token:    getToken(ctx),
		Identity: inIdentity,
		Parent:   req.Parent,
	})

	if err != nil {
		return nil, errors.Wrap(err, "error creating identity")
	}

	outIdentity, err := serializeIdentity(resultIdentity)
	if err != nil {
		return nil, errors.Wrap(err, "error serializing identity")
	}

	return outIdentity, nil
}

func (s *server) UpdateIdentity(ctx context.Context, req *pb.UpdateIdentityRequest) (*pb.Identity, error) {
	return nil, nil
}

func (s *server) DeleteIdentity(ctx context.Context, req *pb.DeleteIdentityRequest) (*empty.Empty, error) {
	return nil, nil
}

func getToken(ctx context.Context) string {
	if mdata, ok := metadata.FromIncomingContext(ctx); ok {
		if auth, ok := mdata["authorization"]; ok {
			if len(auth) > 0 {
				idx := strings.Index(auth[0], " ")
				if auth[0][:idx] == "Bearer" {
					return auth[0][idx+1:]
				}
			}
		}
	}

	return ""
}

func deserializeAccount(a *pb.Account) models.Account {
	return models.Account{
		Name:        a.Name,
		DisplayName: a.DisplayName,
	}
}

func serializeAccount(a models.Account) (*pb.Account, error) {
	createTime, err := ptypes.TimestampProto(a.CreateTime)
	if err != nil {
		return nil, err
	}

	updateTime, err := ptypes.TimestampProto(a.UpdateTime)
	if err != nil {
		return nil, err
	}

	return &pb.Account{
		Name:        a.Name,
		CreateTime:  createTime,
		UpdateTime:  updateTime,
		DisplayName: a.DisplayName,
		Root:        a.Root,
	}, nil
}

func deserializeUser(u *pb.User) models.User {
	return models.User{
		Name:        u.Name,
		IsRoot:      u.IsRoot,
		DisplayName: u.DisplayName,
	}
}

func serializeUser(u models.User) (*pb.User, error) {
	createTime, err := ptypes.TimestampProto(u.CreateTime)
	if err != nil {
		return nil, err
	}

	updateTime, err := ptypes.TimestampProto(u.UpdateTime)
	if err != nil {
		return nil, err
	}

	return &pb.User{
		Name:        u.Name,
		CreateTime:  createTime,
		UpdateTime:  updateTime,
		IsRoot:      u.IsRoot,
		DisplayName: u.DisplayName,
	}, nil
}

func serializeIdentity(i models.Identity) (*pb.Identity, error) {
	createTime, err := ptypes.TimestampProto(i.CreateTime)
	if err != nil {
		return nil, err
	}

	updateTime, err := ptypes.TimestampProto(i.UpdateTime)
	if err != nil {
		return nil, err
	}

	identity := &pb.Identity{
		Name:       i.Name,
		CreateTime: createTime,
		UpdateTime: updateTime,
	}

	switch i.AuthMethod {
	case models.AuthMethodPassword:
		identity.AuthMethod = pb.Identity_AUTH_METHOD_PASSWORD
		identity.AuthDetails = &pb.Identity_Password{
			Password: i.Password,
		}
	}

	return identity, nil
}

func deserializeIdentity(u *pb.Identity) (models.Identity, error) {
	identity := models.Identity{
		Name: u.Name,
	}

	switch u.AuthMethod {
	case pb.Identity_AUTH_METHOD_UNSPECIFIED:
		return models.Identity{}, errors.New("auth_method is required")
	case pb.Identity_AUTH_METHOD_PASSWORD:
		identity.AuthMethod = models.AuthMethodPassword
		identity.Password = u.GetPassword()
	}

	return identity, nil
}
