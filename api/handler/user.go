package handler

import (
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	token "auth/api/token"
	"auth/config"
	pb "auth/genprotos"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type changePass struct{
	CurrentPassword string
	NewPassword string
}

type resetPass struct{
	ResetPassword string
	NewPassword string
}


// RegisterUser registers a new user
// @Summary Register a new user
// @Description Create a new user with email, password and username
// @Tags User
// @Accept json
// @Produce json
// @Param user body pb.RegisterUserRequest true "Register User Payload"
// @Success 201 {object} map[string]string "User created successfully"
// @Failure 400 {object} map[string]string "Invalid request data or email format"
// @Failure 409 {object} map[string]string "User already exists"
// @Failure 500 {object} map[string]string "Failed to create user"
// @Router /auth/register [post]
func (h *Handler) RegisterUser(ctx *gin.Context){
	user := pb.RegisterUserRequest{}
	err := ctx.BindJSON(&user)
	if err != nil{
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	emailRegex := `^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	if !re.MatchString(user.Email){
		ctx.JSON(http.StatusBadRequest, gin.H{"error" : "Invalid email format"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil{
		ctx.JSON(http.StatusInternalServerError, gin.H{"error" : "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)

	_, err = h.UserStorage.User().RegisterUser(&user)
	if err != nil{
		if status.Code(err) == codes.AlreadyExists{
			ctx.JSON(http.StatusConflict, gin.H{"error" : "User already exists"})
		}else{
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		}
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message" : "User created successfully"})
}


// LoginUser authenticates a user and returns JWT token
// @Summary Login user
// @Description Authenticate with email and password, returns JWT token and basic user info
// @Tags User
// @Accept json
// @Produce json
// @Param credentials body pb.LoginUserRequest true "Login credentials"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 400 {object} map[string]string "Invalid request body or server error"
// @Failure 401 {object} map[string]string "Invalid email or password"
// @Router /auth/login [post]
func (h *Handler) LoginUser(ctx *gin.Context){
	user := pb.LoginUserRequest{}
	err := ctx.ShouldBindJSON(&user)
	if err != nil{
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"} )
		return
	}

	res, err := h.UserStorage.User().LoginUser(&user)
	if err != nil{
		if err.Error() == "invalid email or password"{
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error" : err.Error()})
		return
	}

	t := token.GenereteJWTToken(res)
	ctx.JSON(200, t)
}


// UpdateUser updates an existing user's fields (admin or user-self depending on logic)
// @Summary Update user
// @Description Update user fields like email, password, username (supply id in payload)
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user body pb.UpdateUserRequest true "Update User Payload"
// @Success 200 {object} map[string]interface{} "User successfully updated"
// @Failure 400 {object} map[string]string "Invalid request body or nothing to update"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Failed to update user"
// @Router /user [put]
func (h *Handler) UpdateUser(ctx *gin.Context) {
	var user pb.UpdateUserRequest

	if err := ctx.ShouldBindJSON(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid request body",
			"details": err.Error(),
		})
		return
	}

	res, err := h.UserStorage.User().UpdateUser(&user)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "nothing to update"):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "no fields provided to update",
			})
		case strings.Contains(err.Error(), "user not found"):
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to update user",
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "user successfully updated",
		"user": gin.H{
			"id":       res.Id,
			"email":    res.Email,
			"username": res.Username,
			"role":     res.Role,
		},
	})
}


// DeleteUser handles the deletion of a user
// @Summary Delete User
// @Description Delete an existing user
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} map[string]string "Delete Successfully"
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 404 {object} map[string]string "User Not Found"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /user/delete/{id} [delete]
func (h *Handler) DeleteUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "missing user ID in path",
		})
		return
	}

	req := pb.DeleteUserRequest{Id: userID}
	_, err := h.UserStorage.User().DeleteUser(&req)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "user not found"):
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to delete user",
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "user deleted successfully",
	})
}


// GetByIdUser handles retrieving a user by ID
// @Summary Get User By ID
// @Description Retrieve user information using their unique ID
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} pb.GetByIdResponse "Get By ID Successful"
// @Failure 400 {object} map[string]string "Bad Request"
// @Failure 404 {object} map[string]string "User Not Found"
// @Failure 500 {object} map[string]string "Internal Server Error"
// @Router /user/get-by-id/{id} [get]
func (h *Handler) GetByIdUser(ctx *gin.Context) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "missing user ID in path",
		})
		return
	}

	req := pb.GetByIdRequest{Id: userID}
	res, err := h.UserStorage.User().GetByIdUser(&req)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "user not found"):
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to retrieve user",
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "user retrieved successfully",
		"user": gin.H{
			"id":       res.Id,
			"email":    res.Email,
			"username": res.Username,
			"role":     res.Role,
			"password": res.Password,
		},
	})
}

// ChangePassword handles changing user password
// @Summary Change Password
// @Description Change user password
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param ChangePass body changePass true "Change Password"
// @Success 200 {body} string "Password Changed Successfully"
// @Failure 400 {string} string "Error while changing password"
// @Router /user/change-password [post]
func (h *Handler) ChangePassword(ctx *gin.Context) {
	changePas := changePass{}
	if err := ctx.BindJSON(&changePas); err != nil {
		ctx.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)

	changeReq := pb.ChangePasswordRequest{
		Id:              id,
		CurrentPassword: changePas.CurrentPassword,
		NewPassword:     changePas.NewPassword,
	}

	if _, err := h.UserStorage.User().ChangePassword(&changeReq); err != nil {
		ctx.JSON(400, gin.H{"error": "Failed to change password"})
		return
	}

	ctx.JSON(200, gin.H{"message": "Password changed successfully"})
}

// ForgotPassword handles initiating the forgot password process
// @Summary Forgot Password
// @Description Initiate forgot password process
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 200 {body} string "Forgot Password Initiated Successfully"
// @Failure 400 {string} string "Error while initiating forgot password"
// @Router /user/forgot-password [post]
func (h *Handler) ForgotPassword(ctx *gin.Context) {
	cnf := config.Load()
	email, _ := token.GetEmailFromToken(ctx.Request, &cnf)

	if !isValidEmail(email) {
		ctx.JSON(400, gin.H{"error": "Invalid email address"})
		return
	}

	code := rand.Intn(899999) + 100000
	if err := h.redis.SaveToken(email, fmt.Sprintf("%d", code), time.Minute*2); err != nil {
		ctx.JSON(400, gin.H{"error": "Failed to save verification code"})
		return
	}

	ctx.JSON(200, gin.H{"message": "Verification code sent successfully"})
}

func isValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

// ResetPassword handles resetting the user password
// @Summary Reset Password
// @Description Reset user password
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Param ResetPass body resetPass true "Reset Password"
// @Success 200 {string} string "Password Reset Successfully"
// @Failure 400 {string} string "Error while resetting password"
// @Router /user/reset-password [post]
func (h *Handler) ResetPassword(ctx *gin.Context) {
	resetPas := resetPass{}
	if err := ctx.BindJSON(&resetPas); err != nil {
		ctx.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)
	email, _ := token.GetEmailFromToken(ctx.Request, &cnf)

	tokenValue, err := h.redis.Get(email)
	if err != nil {
		ctx.JSON(400, gin.H{"error": "Verification code expired or invalid"})
		return
	}

	if tokenValue != resetPas.ResetPassword {
		ctx.JSON(400, gin.H{"error": "Invalid reset token"})
		return
	}

	resetReq := pb.ResetPasswordRequest{
		Id:         id,
		ResetToken: resetPas.ResetPassword,
		Password:   resetPas.NewPassword,
	}

	if _, err := h.UserStorage.User().ResetPassword(&resetReq); err != nil {
		ctx.JSON(400, gin.H{"error": "Failed to reset password"})
		return
	}

	ctx.JSON(200, gin.H{"message": "Password reset successfully"})
}

// DeleteProfil handles the deletion of a Profile
// @Summary Delete Profile
// @Description Delete an existing Profile
// @Tags User
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 200 {string} string "Delete Successful"
// @Failure 400 {string} string "Error while deleting user"
// @Router /user [delete]
func (h *Handler) DeleteProfil(ctx *gin.Context) {
	cnf := config.Load()
	id, _ := token.GetIdFromToken(ctx.Request, &cnf)

	if _, err := h.UserStorage.User().DeleteUser(&pb.DeleteUserRequest{Id: id}); err != nil {
		ctx.JSON(400, gin.H{"error": "Failed to delete profile"})
		return
	}

	ctx.JSON(200, gin.H{"message": "User deleted successfully"})
}

// GetAllUsers handles the retrieval of all users
// @Summary Get All Users
// @Description Retrieve a list of all users with pagination
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Limit" default(10)
// @Param offset query int false "Offset" default(0)
// @Success 200 {object} pb.GetAllUsersResponse "List of Users"
// @Failure 400 {string} string "Error while retrieving users"
// @Router /admin/all [get]
func (h *Handler) GetAllUsers(ctx *gin.Context) {
	limit, err1 := strconv.Atoi(ctx.DefaultQuery("limit", "10"))
	offset, err2 := strconv.Atoi(ctx.DefaultQuery("offset", "0"))
	if err1 != nil || err2 != nil {
		ctx.JSON(400, gin.H{"error": "Invalid query parameters"})
		return
	}

	req := &pb.GetAllUsersRequest{
		Limit:  int32(limit),
		Offset: int32(offset),
	}

	res, err := h.UserStorage.User().GetAllUsers(req)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to retrieve users"})
		return
	}

	ctx.JSON(200, res)
}
