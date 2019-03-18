package main

import (
	"context"
	"log"
	"net"
	"net/http"

	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"

	"github.com/json-multiplex/iam-service/internal/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/json-multiplex/iam-service/generated/v0"
)

type server struct {
	Service service.Service
}

func serializeUser(u service.User) (*pb.User, error) {
	createTime, err := ptypes.TimestampProto(u.CreateTime)
	if err != nil {
		return nil, err
	}

	updateTime, err := ptypes.TimestampProto(u.UpdateTime)
	if err != nil {
		return nil, err
	}

	deleteTime, err := ptypes.TimestampProto(u.DeleteTime)
	if err != nil {
		return nil, err
	}

	return &pb.User{
		Name:        u.Name,
		CreateTime:  createTime,
		UpdateTime:  updateTime,
		DeleteTime:  deleteTime,
		IsRoot:      u.IsRoot,
		DisplayName: u.DisplayName,
	}, nil
}

func deserializeIdentity(u *pb.Identity) (service.Identity, error) {
	identity := service.Identity{
		Name: u.Name,
	}

	switch u.AuthMethod {
	case pb.Identity_AUTH_METHOD_UNSPECIFIED:
		return service.Identity{}, errors.New("auth_method is required")
	case pb.Identity_AUTH_METHOD_PASSWORD:
		identity.AuthMethod = service.AuthMethodPassword
		identity.Password = u.GetPassword()
	}

	return identity, nil
}

func serializeIdentity(i service.Identity) (*pb.Identity, error) {
	createTime, err := ptypes.TimestampProto(i.CreateTime)
	if err != nil {
		return nil, err
	}

	updateTime, err := ptypes.TimestampProto(i.UpdateTime)
	if err != nil {
		return nil, err
	}

	deleteTime, err := ptypes.TimestampProto(i.DeleteTime)
	if err != nil {
		return nil, err
	}

	identity := &pb.Identity{
		Name:       i.Name,
		CreateTime: createTime,
		UpdateTime: updateTime,
		DeleteTime: deleteTime,
	}

	switch i.AuthMethod {
	case service.AuthMethodPassword:
		identity.AuthMethod = pb.Identity_AUTH_METHOD_PASSWORD
		identity.AuthDetails = &pb.Identity_Password{
			Password: i.Password,
		}
	}

	return identity, nil
}

func deserializeUser(u *pb.User) service.User {
	return service.User{
		Name:        u.Name,
		IsRoot:      u.IsRoot,
		DisplayName: u.DisplayName,
	}
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	var token string
	if mdata, ok := metadata.FromIncomingContext(ctx); ok {
		if auth, ok := mdata["authorization"]; ok {
			if len(auth) > 0 {
				token = auth[0]
			}
		}
	}

	inUser := deserializeUser(req.User)

	resultUser, err := s.Service.CreateUser(ctx, service.CreateUserRequest{
		Token: token,
		User:  inUser,
	})

	if err != nil {
		return nil, errors.Wrap(err, "error creating user")
	}

	outUser, err := serializeUser(resultUser)
	if err != nil {
		return nil, errors.Wrap(err, "error serializing user")
	}

	return outUser, nil
}

func (s *server) CreateIdentity(ctx context.Context, req *pb.CreateIdentityRequest) (*pb.Identity, error) {
	var token string
	if mdata, ok := metadata.FromIncomingContext(ctx); ok {
		if auth, ok := mdata["authorization"]; ok {
			if len(auth) > 0 {
				token = auth[0]
			}
		}
	}

	inIdentity, err := deserializeIdentity(req.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "error deserializing identity")
	}

	resultIdentity, err := s.Service.CreateIdentity(ctx, service.CreateIdentityRequest{
		Token:    token,
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

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	grpcServer := grpc.NewServer()
	pb.RegisterIAMServer(grpcServer, &server{})
	reflection.Register(grpcServer)

	l, err := net.Listen("tcp", ":3000")
	if err != nil {
		log.Fatalf("failed to listen and serve grpc: %v", err)
	}

	go grpcServer.Serve(l)

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	pb.RegisterIAMHandlerFromEndpoint(ctx, mux, ":3000", opts)

	if err := http.ListenAndServe(":4000", mux); err != nil {
		log.Fatalf("failed to listen and serve http: %v", err)
	}
}
