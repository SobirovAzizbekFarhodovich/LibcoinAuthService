package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	pb "auth/genprotos"

	"golang.org/x/crypto/bcrypt"
)

type UserStorage struct{
	db 	*sql.DB
}

func NewUserStorage(db *sql.DB) *UserStorage{
	return &UserStorage{db: db}
}

const emailRegex = `^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

func isValidEmail(email string) bool{
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}

func (u *UserStorage) RegisterUser(user *pb.RegisterUserRequest)(*pb.RegisterUserResponse, error){
	if !isValidEmail(user.Email){
		return nil, errors.New("invalid email format")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil{
		return nil, err
	}

	query := `INSERT INTO users(email, password, username) VALUES($1, $2, $3)`
	_, err = u.db.Exec(query,user.Email, hashedPassword, user.Username)
	if err != nil{
		return nil, err
	}	
	return &pb.RegisterUserResponse{}, nil
}

func (u *UserStorage) LoginUser(user *pb.LoginUserRequest)(*pb.LoginUserResponse, error){
	query := `SELECT id, email, password, username, role FROM users WHERE email = $1 AND deleted_at = 0`
	row := u.db.QueryRow(query,user.Email)
	res := pb.LoginUserResponse{}
	err := row.Scan(
		&res.Id,
		&res.Email,
		&res.Password,
		&res.Username,
		&res.Role,
	)	
	if err != nil{
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invalid email or password")
		}
		return nil, err
	}

	fmt.Println("hash password >>>>>>>>>>", res.Password, "\npassword >>>>>>>", user.Password)

	err = bcrypt.CompareHashAndPassword([]byte(res.Password), []byte(user.Password))
	if err != nil{
		return nil, fmt.Errorf("invalid email or password")
	}
	return &res, nil
}

func (u *UserStorage) UpdateUser(req *pb.UpdateUserRequest)(*pb.UpdateUserResponse, error){
	query := `UPDATE users SET `
	var condition []string
	var args []interface{}

	if req.Email != "" && req.Email != "string" {
		condition = append(condition, fmt.Sprintf("email = $%d", len(args) + 1))
	}
	if req.Password != "" && req.Password != "string" {
		condition = append(condition, fmt.Sprintf("password = $%d", len(args) + 1))
	}
	if req.Username != "" && req.Username != "string" {
		condition = append(condition, fmt.Sprintf("username = $%d", len(args) + 1))
	}

	if len(condition) == 0{
			return nil, errors.New("nothing to update")
	}

	query += strings.Join(condition, ", ")
	query += fmt.Sprintf(" WHERE id = $%d RETURNING id, email, password, username, role", len(args) + 1)
	args = append(args, req.Id)

	res := pb.UpdateUserResponse{}
	row := u.db.QueryRow(query, args...)

	err := row.Scan(&res.Id, &res.Email, &res.Password, &res.Username, &res.Role)
	if err != nil{
		return nil, err
	}
	return &res, nil
}

func (u *UserStorage) DeleteUser(id *pb.DeleteUserRequest)(*pb.DeleteUserResponse, error){
	query := `Update users SET deleted_at = $2 WHERE id = $1 AND deleted_at = 0`

	_, err := u.db.Exec(query, id.Id, time.Now().Unix())
	if err != nil{
		return  nil, err
	}
	return &pb.DeleteUserResponse{}, nil
}

func (u *UserStorage) GetByIdUser(id *pb.GetByIdRequest)(*pb.GetByIdResponse, error){
	query := `SELECT id, email, username, role FROM users WHERE id = $1 AND deleted_at = 0`
	row := u.db.QueryRow(query, id.Id)
	user := pb.GetByIdResponse{}
	err := row.Scan(
		&user.Id,
		&user.Email,
		&user.Username,
		&user.Role,
	)

	if err != nil{
		if err == sql.ErrNoRows{
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return  &user, nil
}

func (u *UserStorage) GetAllUsers(req *pb.GetAllUsersRequest)(*pb.GetAllUsersResponse, error){
	query := `SELECT id, email, username, role FROM users WHERE deleted_at = 0 LIMIT $1 OFFSET $2`
	rows, err := u.db.Query(query, req.Limit, req.Offset)
	if err != nil{
		return nil, err
	}
	defer rows.Close()

	var users []*pb.GetByIdResponse
	for rows.Next(){
		var user pb.GetByIdResponse
		err := rows.Scan(
			&user.Id,
			&user.Email,
			&user.Username,
			&user.Role,
		)
		if err != nil{
			return  nil, err
		}
		users = append(users, &user)
	}

	if err := rows.Err(); err != nil{
		return nil, err
	}
		return &pb.GetAllUsersResponse{
			User: users,
		}, nil
}

func (u *UserStorage) ResetPassword(req *pb.ResetPasswordRequest)(*pb.ResetPasswordResponse, error){
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil{
		return nil, err
	}

	query := `UPDATE users SET password = $2 WHERE id = $1 AND deleted_at = 0`

	_, err = u.db.Exec(query, req.Id, string(hashedPassword))
	if err != nil{
		return nil, err
	}
	return &pb.ResetPasswordResponse{}, nil
}


func (u *UserStorage) ForgotPassword(req *pb.ForgotPasswordRequest)(*pb.ForgotPasswordResponse, error){
	return &pb.ForgotPasswordResponse{}, nil
}

func (u *UserStorage) ChangePassword(req *pb.ChangePasswordRequest)(*pb.ChangePasswordResponse, error){
	var currentHashedPassword string
	query := `SELECT password FROM users WHERE id = $1 AND deleted_at = 0`
	err := u.db.QueryRow(query, req.Id).Scan(&currentHashedPassword)
	if err != nil{
		if err == sql.ErrNoRows{
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(currentHashedPassword), []byte(req.CurrentPassword))
	if err != nil{
		return nil, fmt.Errorf("invalid current password")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil{
		return nil, fmt.Errorf("failed to hash new password")
	}

	updateQuery := `UPDATE users SET password = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`

	_, err = u.db.Exec(updateQuery, req.Id, hashedPassword, time.Now())
	if err != nil{
		return  nil, err
	}
	return &pb.ChangePasswordResponse{}, nil

}

func (u *UserStorage) GetUserByEmail(email string) (*pb.UpdateUserResponse, error){
	var user pb.UpdateUserResponse
	query := "SELECT id, email, username FROM users WHERE email = $1 AND deleted_at = 0"
	row := u.db.QueryRow(query, email)
	err := row.Scan(&user.Id, &user.Email, &user.Username)
	if err != nil{
		if err == sql.ErrNoRows{
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}