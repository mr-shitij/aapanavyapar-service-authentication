package authentication_services

import (
	"aapanavyapar_service_authentication/data_base/data_services"
	"aapanavyapar_service_authentication/data_base/helpers"
	"aapanavyapar_service_authentication/data_base/structs"
	"aapanavyapar_service_authentication/pb"
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/o1egl/paseto/v2"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"strconv"
	"time"
)

type AuthenticationServer struct {
	data *data_services.DataServices
}

func NewAuthenticationServer() (*AuthenticationServer, error) {

	auth := &AuthenticationServer{
		data: data_services.NewDbConnection(),
	}
	err := auth.data.LoadUserContactDataInCash(context.Background())
	if err != nil {
		return nil, err
	}
	fmt.Println("Cash Data Is Loaded : ")

	return auth, nil
}

func PrintClaimsOfAuthToken(token string) {
	var newJsonToken paseto.JSONToken
	var newFooter string
	err := paseto.Decrypt(token, []byte(os.Getenv("AUTH_TOKEN_SECRETE")), &newJsonToken, &newFooter)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Auth Token")
		fmt.Println("Audience", newJsonToken.Audience)
		fmt.Println("Subject : ", newJsonToken.Subject)
		fmt.Println("Expiration : ", newJsonToken.Expiration)
		fmt.Println("IssueAt : ", newJsonToken.IssuedAt)
		fmt.Println("Issuer : ", newJsonToken.Issuer)
		var val bool
		_ = newJsonToken.Get("authorized", &val)
		fmt.Println("Authorized : ", val)
		fmt.Println("Footer : ", newFooter)
	}
}

func PrintClaimsOfRefreshToken(token string) {
	var newJsonToken paseto.JSONToken
	var newFooter string
	err := paseto.Decrypt(token, []byte(os.Getenv("REFRESH_TOKEN_SECRETE")), &newJsonToken, &newFooter)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Refresh Token")
		fmt.Println("Audience", newJsonToken.Audience)
		fmt.Println("Subject : ", newJsonToken.Subject)
		fmt.Println("Expiration : ", newJsonToken.Expiration)
		fmt.Println("IssueAt : ", newJsonToken.IssuedAt)
		fmt.Println("Issuer : ", newJsonToken.Issuer)
		var val bool
		_ = newJsonToken.Get("authorized", &val)
		fmt.Println("Authorized : ", val)
		fmt.Println("Footer : ", newFooter)
	}
}

func (authenticationServer *AuthenticationServer) GetNewToken(ctx context.Context, request *pb.NewTokenRequest) (*pb.NewTokenResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	receivedRefreshToken, err := authenticationServer.data.ValidateToken(ctx, request.GetRefreshToken(), os.Getenv("REFRESH_TOKEN_SECRETE"), data_services.GetNewToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	ok, token, err := authenticationServer.data.ValidateRefreshTokenAndGenerateNewAuthToken(ctx, request.GetRefreshToken(), receivedRefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Token")
	}

	if ok {
		return &pb.NewTokenResponse{
			Token: token,
		}, nil
	}

	return nil, status.Errorf(codes.InvalidArgument, "Invalid Token")
}

func (authenticationServer *AuthenticationServer) Signup(ctx context.Context, request *pb.SignUpRequest) (*pb.SignUpResponse, error) {

	fmt.Println("\n Signup RPC \n")

	fmt.Println("\n Checking For API Key Validation")
	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}
	fmt.Println("\n API Key Validated")

	fmt.Println("Moving For Sanitization and validation")
	user, err := helpers.SanitizeAndValidate(request)
	fmt.Println("Sanitization and validation completed")

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Unable To Validate Provided Inputs")
	}

	fmt.Println("Getting Contact List From Cash")
	if _, err := authenticationServer.data.GetContactListDataFromCash(ctx, user.PhoneNo); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "User Already Exist")
	}
	fmt.Println("Received Contact List Form Cash")

	fmt.Println("Getting Temporary Contact From Cash")
	if _, err := authenticationServer.data.GetTempContactFromCash(ctx, user.PhoneNo); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "Process In Progress")
	}
	fmt.Println("Received Temporary Contact From Cash")

	fmt.Println("Generating Random UUID")
	userId, err := uuid.NewRandom()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable TO Generate UUID")
	}
	fmt.Println("UUID Generated")

	fmt.Println("Start to hash password")
	cost, _ := strconv.Atoi(os.Getenv("cost"))
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.GetPassword()), cost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Hash")
	}
	fmt.Println("Hashing Completed")

	fmt.Println("Starting To create Temporary user in cash")
	err = authenticationServer.data.CreateTemporaryUserInCash(ctx, &structs.UserData{
		UserId:   userId.String(),
		Username: user.GetUsername(),
		Password: string(hashedPassword),
		PhoneNo:  user.GetPhoneNo(),
		Email:    user.GetEmail(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Add User To Cash")
	}
	fmt.Println("Temporary user is created")

	fmt.Println("Setting temp contact to cash")
	err = authenticationServer.data.SetTempContactToCash(ctx, user.PhoneNo, userId.String())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Add User To Cash Of Waiting users")
	}
	fmt.Println("Temp contact to cash is set")

	fmt.Println("Generating Refresh and Auth Token")
	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, userId.String(), false, []int{data_services.GetNewToken, data_services.ResendOTP, data_services.ConformContact})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token")
	}
	fmt.Println("Generated Refresh and Auth Token")

	fmt.Println("Sending OTP")
	err = authenticationServer.data.GenerateAndSendOTP(ctx, userId.String(), user.GetPhoneNo(), 0, data_services.Validation5Min)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Send OTP")
	}
	fmt.Println("OTP is sent")

	fmt.Println("\n Signup Completed")
	return &pb.SignUpResponse{
		ResponseData: &pb.ResponseData{
			Token:        authToken,
			RefreshToken: refreshToken,
		},
		Authorized: false,
	}, nil
}

func (authenticationServer *AuthenticationServer) SignIn(ctx context.Context, request *pb.SignInRequest) (*pb.SignInResponse, error) {

	fmt.Println("\n SignIn \n")

	fmt.Println("Checking API Key")
	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}
	fmt.Println("Checked API Key")

	fmt.Println("Sanitizing and Validation Started")
	phoneNo, err := helpers.SanitizeAndValidatePhoneNumber(request.PhoneNo)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Unable to Validate Inputs")
	}

	if _, err := authenticationServer.data.GetContactListDataFromCash(ctx, request.PhoneNo); err != nil {
		return nil, status.Errorf(codes.NotFound, "User Not Exist")

	}

	password, err := helpers.SanitizeAndValidatePassword(request.Password)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Unable to Validate Inputs")
	}
	fmt.Println("Sanitization and validation completed")

	err = helpers.ContextError(ctx)
	if err != nil {
		fmt.Println(err)
		return nil, status.Errorf(codes.DeadlineExceeded, "Time Out")
	}
	fmt.Println("Sanitization and Validation Completed")

	fmt.Println("Started SignIn Process")
	userId, err := authenticationServer.data.SignIn(phoneNo, password)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "Unable To Authenticate")
	}
	fmt.Println("Completed SignIn Process")

	fmt.Println("Generating token")
	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, userId, true, []int{data_services.LogOut, data_services.GetNewToken, data_services.External})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token")
	}
	fmt.Println("Generated token")

	fmt.Println("SignIn Completed")
	return &pb.SignInResponse{
		ResponseData: &pb.ResponseData{
			Token:        authToken,
			RefreshToken: refreshToken,
		},
	}, nil

}

func (authenticationServer *AuthenticationServer) Logout(ctx context.Context, request *pb.LogoutRequest) (*pb.LogoutResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.LogOut)
	if err != nil {
		return &pb.LogoutResponse{Status: false}, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	err = authenticationServer.data.DelDataFromCash(ctx, token.Subject) // Do care for refresh token
	if err != nil {
		// Token Expired or Internal Discrepancies.
	}

	return &pb.LogoutResponse{Status: true}, nil
}

func (authenticationServer *AuthenticationServer) ContactConformation(ctx context.Context, request *pb.ContactConformationRequest) (*pb.ContactConformationResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.ConformContact)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	// Here to
	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}
	if authorized {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token") //If Occur Then Serious Data Breach From Internal Organization; Change Token Generation Credentials.
	}
	// Here Extra Check.

	cashVal, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "OTP Token Not Found")
	}

	fmt.Println("Val : ", cashVal)
	fmt.Println("Requested OTP : ", request.GetOtp())

	var val structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(cashVal), &val)

	if val.OTP == request.GetOtp() {

		data, err := authenticationServer.data.GetTemporaryUserFromCash(ctx, token.Audience)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "Please Try Again")
		}

		// From Here
		if val.PhoneNo != data.PhoneNo {
			return nil, status.Errorf(codes.Aborted, "Unauthenticated User") //If Occur Then Serious Data Breach From Internal Organization; Change Token Generation Credentials.
		}
		// To Here Extra Check

		err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
		if err != nil {
			// Capture Error When Logging
			// Inconsistency with cash.
		}
		fmt.Println("Refresh From Cash Delete : ", err)

		err = authenticationServer.data.DelDataFromCash(ctx, token.Audience)
		fmt.Println("OTP Data From Cash Delete : ", err)

		err = authenticationServer.data.DelTempContactFromCash(ctx, data.PhoneNo)
		fmt.Println("Contact From Cash Delete : ", err)

		err = authenticationServer.data.DelTemporaryUserFromCash(ctx, token.Audience)
		if err != nil {
			// Capture Error When Logging
			// DataBase Problem or Data Expired
		}
		fmt.Println("Deleting Cash User :  ", err)

		err = authenticationServer.data.CreateUser(ctx, data)
		if err != nil {
			return nil, status.Errorf(codes.Unknown, "Unable To Create User") // If User Already Exist Then Report Inconsistency with cash and database
		}

		refreshTok, authTok, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, token.Audience, true, []int{data_services.LogOut, data_services.GetNewToken, data_services.External})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token")
		}

		return &pb.ContactConformationResponse{
			Token:        authTok,
			RefreshToken: refreshTok,
		}, nil

	}
	return nil, status.Errorf(codes.InvalidArgument, "Invalid OTP")
}

func (authenticationServer *AuthenticationServer) ResendOTP(ctx context.Context, request *pb.ResendOTPRequest) (*pb.ResendOTPResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.ResendOTP)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	// From Here
	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}
	if authorized {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token") // Some Problem occurred Request made with token is of authorized user who has no permission to access this rpc.
	}
	// To Here Extra Check.

	val, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "OTP Token Not Found") // Some Problem Occurred Sent OTP Is Expired Or Not Sent.
	}

	var data structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(val), &data)

	fmt.Println("Data Resend Times : ", data.ResendTimes)
	fmt.Println("Time Of OTP Sending : ", data.Time)
	fmt.Println("Current Time  : ", time.Now())

	// If OTPResponse_Ok then TimeToWaitForNextRequest is time after which you can get *next* otp if required
	// If OTPResponse_NotOk then TimeToWaitForNextRequest is time to wait to get otp.

	switch data.ResendTimes {
	case 0:
		err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 1, data_services.Validation5Min)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unable To Send OTP")
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_OK,
			TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation5Min),
		}, nil

	case 1:
		if time.Now().Sub(data.Time) >= data_services.Validation5Min {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 2, data_services.Validation10Min)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Unable To Send OTP")
			}

			return &pb.ResendOTPResponse{
				Response:                 pb.OTPResponse_OK,
				TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation10Min),
			}, nil
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_NotOk,
			TimeToWaitForNextRequest: ptypes.DurationProto(time.Now().Sub(data.Time)),
		}, nil

	case 2:
		if time.Now().Sub(data.Time) >= data_services.Validation10Min {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 3, data_services.Validation15Min)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Unable To Send OTP")
			}

			return &pb.ResendOTPResponse{
				Response:                 pb.OTPResponse_OK,
				TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation15Min),
			}, nil
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_NotOk,
			TimeToWaitForNextRequest: ptypes.DurationProto(time.Now().Sub(data.Time)),
		}, nil

	case 3:
	default:
		return nil, status.Errorf(codes.ResourceExhausted, "You Exhausted Your OTP Limit")

	}
	return nil, status.Errorf(codes.Unknown, "Unable To Process Request")
}

func (authenticationServer *AuthenticationServer) ForgetPassword(ctx context.Context, request *pb.ForgetPasswordRequest) (*pb.ForgetPasswordResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	phoNo, err := helpers.SanitizeAndValidatePhoneNumber(request.GetPhoNo())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Unable To Validate Inputs")
	}

	id, err := authenticationServer.data.GetContactListDataFromCash(ctx, phoNo)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "Not exist")
	}

	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, id, false, []int{data_services.GetNewToken, data_services.ResendOTP, data_services.ForgetPassword})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token")
	}

	err = authenticationServer.data.GenerateAndSendOTP(ctx, id, phoNo, 0, data_services.Validation5Min)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Send OTP")
	}

	return &pb.ForgetPasswordResponse{
		ResponseData: &pb.ResponseData{
			Token:        authToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func (authenticationServer *AuthenticationServer) ConformForgetPasswordOTP(ctx context.Context, request *pb.ConformForgetPasswordOTPRequest) (*pb.ConformForgetPasswordOTPResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.ForgetPassword)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	// From Here
	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}
	if authorized {
		return nil, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}
	// To Here Extra Check

	cashVal, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "OTP Token Not Found")
	}

	fmt.Println("Val : ", cashVal)
	fmt.Println("Requested OTP : ", request.GetOtp())

	var val structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(cashVal), &val)

	if val.OTP == request.GetOtp() {

		err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
		if err != nil {
			// Capture Error When Logging
			// Inconsistency with cash.
		}
		fmt.Println("Refresh From Cash Delete ", err)

		err = authenticationServer.data.DelDataFromCash(ctx, token.Audience)
		fmt.Println("OTP Data From Cash Delete", err)

		passToken, err := authenticationServer.data.GeneratePassTokenAndAddToCash(ctx, token.Audience, []int{data_services.NewPassToken})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unable To Generate Token")
		}

		return &pb.ConformForgetPasswordOTPResponse{
			NewPassToken: passToken,
		}, nil

	}

	return nil, status.Errorf(codes.PermissionDenied, "Invalid OTP To Get Password")

}

func (authenticationServer *AuthenticationServer) SetNewPassword(ctx context.Context, request *pb.SetNewPasswordRequest) (*pb.SetNewPasswordResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetNewPassToken(), os.Getenv("PASS_TOKEN_SECRETE"), data_services.NewPassToken)
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, status.Errorf(codes.Unauthenticated, "Request With Invalid Token")
	}

	password, err := helpers.SanitizeAndValidatePassword(request.GetNewPassword())
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, status.Errorf(codes.InvalidArgument, "Try With Stronger Password")
	}

	err = authenticationServer.data.UpdatePassword(token.Audience, password)
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, status.Errorf(codes.Internal, "Fail To Update Password")
	}
	return &pb.SetNewPasswordResponse{Status: true}, nil
}
