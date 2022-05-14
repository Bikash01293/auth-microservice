package main

import (
	"auth-micro/pkg/db"
	"auth-micro/pkg/pb"
	"auth-micro/pkg/services"
	"auth-micro/pkg/utils"
	"fmt"
	"log"
	"net"

 	"auth-micro/pkg/config"
	"google.golang.org/grpc"
)

func main() {
	c, err := config.LoadConfig()
	if err != nil {
		log.Fatalln("Failed to load config", err)
	}

	h := db.Init(c.DbUrl)

	jwt := utils.JwtWrapper{
		SecretKey:      c.JwtSecretKey,
		Issuer:         "auth-micro",
		ExpirationHours: 24 * 365,
	}

	lis, err := net.Listen("tcp", c.Port)

	if err != nil {
		log.Fatalln("failed to listening", err)
	}

	fmt.Println("Auth on svc", c.Port)

	s := services.Server{
		H:   h,
		Jwt: jwt,
	}

	grpcServer := grpc.NewServer()

	pb.RegisterAuthServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to Serve", err)
	}

}
