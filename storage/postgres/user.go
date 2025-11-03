package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	// "strings"
	// "time"

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
		&res.Role,
		&res.Username,
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