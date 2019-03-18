bin/iam: $(shell find cmd internal generated/v0 -type f)
	go build -o bin/iam cmd/iam/main.go

generated/v0/iam.pb.go: $(shell find v0 -type f)
	protoc \
		--proto_path=proto_ext \
		--proto_path=v0 \
		--go_out=plugins=grpc:generated/v0 \
		v0/iam.proto

generated/v0/iam.pb.gw.go: $(shell find v0 -type f)
	protoc \
		--proto_path=proto_ext \
		--proto_path=v0 \
		--grpc-gateway_out=logtostderr=true:generated/v0 \
		v0/iam.proto
