package services

import (
	"auth-micro/pkg/db"
	"auth-micro/pkg/models"
	"auth-micro/pkg/pb"
	"auth-micro/pkg/utils"
	"context"
	"net/http"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
}

func (s *Server) Register(ctx context.Context, req *pb.RequestRegister) (*pb.ResponseRegister, error) {
	var user models.User

	result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user)

	if result.Error == nil {
		return &pb.ResponseRegister{
			Status: http.StatusConflict,
			Error:  "E-Mail already exists",
		}, nil
	}

	user.Email = req.Email
	user.Password = utils.HashPassword(req.Password)

	s.H.DB.Create(&user)

	return &pb.ResponseRegister{
		Status: http.StatusCreated,
	}, nil

}

func (s *Server) Login(ctx context.Context, req *pb.RequestLogin) (*pb.ResponseLogin, error) {
	var user models.User
	result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user)

	if result.Error != nil {
		return &pb.ResponseLogin{
			Status: http.StatusNotFound,
			Error:  "user not found",
		}, nil
	}

	match := utils.CheckPasswordHash(req.Password, user.Password)

	if !match {
		return &pb.ResponseLogin{
			Status: http.StatusNoContent,
			Error:  "Password not matched",
		}, nil
	}

	token, _ := s.Jwt.GenerateToken(user)

	return &pb.ResponseLogin{
		Status: http.StatusOK,
		Token:  token,
	}, nil

}

func (s *Server) Validate(ctx context.Context, req *pb.RequestValidate) (*pb.ResponseValidate, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)

	if err != nil {
		return &pb.ResponseValidate{
			Status: http.StatusNotFound,
			Error:  "no token provided",
		}, nil
	}

	var user models.User

	result := s.H.DB.Where(&models.User{Email: claims.Email}).First(&user)

	if result.Error != nil {
		return &pb.ResponseValidate{
			Status: http.StatusNotFound,
			Error:  "user not found",
		}, nil
	}

	return &pb.ResponseValidate{
		Status: http.StatusOK,
		UserId: user.Id,
	}, nil
}
