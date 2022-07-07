proto:
	protoc pkg/pb/*.proto --go_out=plugins=grpc:.
	

auth-server:
	go run cmd/main.go