package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/namsral/flag"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/json-multiplex/iam-service/generated/v0"
	"github.com/json-multiplex/iam-service/internal/service"
	"github.com/json-multiplex/iam-service/internal/store"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	srv, err := newServer()
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	pb.RegisterIAMServer(grpcServer, &srv)
	reflection.Register(grpcServer)

	l, err := net.Listen("tcp", ":3000")
	if err != nil {
		return errors.Wrap(err, "failed to listen and serve grpc")
	}

	go grpcServer.Serve(l)

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	pb.RegisterIAMHandlerFromEndpoint(ctx, mux, ":3000", opts)

	return http.ListenAndServe(":4000", mux)
}

func newServer() (server, error) {
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "IAM", 0)

	var dbAddr string
	fs.StringVar(&dbAddr, "db_addr", "", "db connection string")

	var tokenSignKeyPEM string
	fs.StringVar(&tokenSignKeyPEM, "token_sign_key", "", "PEM-encoded key for signing tokens")

	var tokenVerifyKeyPEM string
	fs.StringVar(&tokenVerifyKeyPEM, "token_verify_key", "", "PEM-encoded key for verifying tokens")

	fs.Parse(os.Args[1:])

	db, err := sqlx.Open("postgres", dbAddr)
	if err != nil {
		return server{}, errors.Wrap(err, "failed to open database connection")
	}

	var tokenSignKey *rsa.PrivateKey
	var tokenVerifyKey *rsa.PublicKey

	if block, _ := pem.Decode([]byte(tokenSignKeyPEM)); block != nil {
		tokenSignKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return server{}, errors.Wrap(err, "error parsing token sign key")
		}
	}

	if block, _ := pem.Decode([]byte(tokenVerifyKeyPEM)); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return server{}, errors.Wrap(err, "error parsing token verify key")
		}

		var ok bool
		tokenVerifyKey, ok = key.(*rsa.PublicKey)
		if !ok {
			return server{}, errors.New("verify key must be RSA")
		}
	}

	return server{
		Service: service.Service{
			Store: &store.DBStore{
				DB: db,
			},
			TokenSignKey:          tokenSignKey,
			TokenVerifyKey:        tokenVerifyKey,
			TokenExpirationPeriod: 24 * time.Hour,
		},
	}, nil
}
