package storage

import pb "auth/genprotos"

type StorageI interface{
	User() UserI
}

type UserI interface{
	RegisterUser(user *pb.RegisterUserRequest)(*pb.RegisterUserResponse, error)
	LoginUser(user *pb.LoginUserRequest)(*pb.LoginUserResponse, error)
	GetByIdUser(id *pb.GetByIdRequest)(*pb.GetByIdResponse, error)
	UpdateUser(req *pb.UpdateUserRequest)(*pb.UpdateUserResponse, error)
	DeleteUser(id *pb.DeleteUserRequest)(*pb.DeleteUserResponse,error)
	GetAllUsers(req *pb.GetAllUsersRequest)(*pb.GetAllUsersResponse, error)
	ChangePassword(req *pb.ChangePasswordRequest)(*pb.ChangePasswordResponse, error)
	ForgotPassword(req *pb.ForgotPasswordRequest)(*pb.ForgotPasswordResponse, error)
	ResetPassword(req *pb.ResetPasswordRequest)(*pb.ResetPasswordResponse, error)

}