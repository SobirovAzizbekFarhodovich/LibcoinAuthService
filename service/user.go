package service

import (
	"context"
	"errors"

	pb "auth/genprotos"
	s "auth/storage"
)

type UserService struct{
	stg s.StorageI
	pb.UnimplementedUserServiceServer
}

func NewUserService(stg s.StorageI) *UserService{
	return &UserService{stg: stg}
}

var ErrUserAlreadyExists = errors.New("user already exists")

func (s *UserService) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest)(*pb.RegisterUserResponse, error){
	existingUser, err := s.stg.User().GetUserByEmail(req.Id)
	if err != nil{
		return nil, err
	}
	if existingUser != nil{
		return nil, ErrUserAlreadyExists
	}

	_, err = s.stg.User().RegisterUser(req)
	if err != nil{
		return nil, err
	}
	return &pb.RegisterUserResponse{}, nil
}

func (s *UserService) LoginUser(ctx context.Context, login *pb.LoginUserRequest)(*pb.LoginUserResponse, error){
	user, err := s.stg.User().LoginUser(login)
	if err != nil{
		return nil, err
	}
	return user, nil
}

func (s *UserService) GetById(ctx context.Context, id *pb.GetByIdRequest)(*pb.GetByIdResponse, error){
	user, err := s.stg.User().GetByIdUser(id)
	if err != nil{
		return nil, err
	}
	return user, nil
}

func (s *UserService) GetAllUsers(ctx context.Context, req *pb.GetAllUsersRequest)(*pb.GetAllUsersResponse, error){
	user, err := s.stg.User().GetAllUsers(req)
	if err != nil{
		return nil, err
	}
	return user, nil
}

func (s *UserService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest)(*pb.UpdateUserResponse, error){
	res, err := s.stg.User().UpdateUser(req)
	if err != nil{
		return nil, err
	}
	return res, nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest)(*pb.DeleteUserResponse, error){
	void, err := s.stg.User().DeleteUser(req)
	if err != nil{
		return nil, err
	}
	return void, nil
}

func (s *UserService) ForgotPassword(ctx context.Context, req *pb.ForgotPasswordRequest)(*pb.ForgotPasswordResponse, error){
	void, err := s.stg.User().ForgotPassword(req)
	if err != nil{
		return nil, err
	}
	return void, nil
}

func (s *UserService) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest)(*pb.ResetPasswordResponse, error){
	void, err := s.stg.User().ResetPassword(req)
	if err != nil{
		return nil, err
	}
	return void, nil
}

func (s *UserService) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest)(*pb.ChangePasswordResponse, error){
	void, err := s.stg.User().ChangePassword(req)
	if err != nil{
		return nil, err
	}
	return void, nil
}