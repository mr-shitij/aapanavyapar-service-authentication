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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
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
		return nil, err
	}

	ok, token, err := authenticationServer.data.ValidateRefreshTokenAndGenerateNewAuthToken(ctx, request.GetRefreshToken(), receivedRefreshToken)
	if err != nil {
		return nil, err
	}

	if ok {
		return &pb.NewTokenResponse{
			Token: token,
		}, nil
	}

	return nil, status.Errorf(codes.InvalidArgument, "Invalid Token")
}

func (authenticationServer *AuthenticationServer) Signup(ctx context.Context, request *pb.SignUpRequest) (*pb.SignUpResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	user, err := helpers.SanitizeAndValidate(request)
	fmt.Println("Sanitization and validation completed")

	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Code(pb.ProblemCode_NoUserNameIsProvided):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_NoUserNameIsProvided,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_NoPhoneNumberIsProvided):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_NoPhoneNumberIsProvided,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_NoPasswordIsProvided):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_NoPasswordIsProvided,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_InvalidPasswordLength):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_InvalidPasswordLength,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_InvalidPhoneNumber):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_InvalidPhoneNumber,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_InvalidPinCode):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_InvalidPinCode,
					},
					Authorized: false,
				}, nil
			case codes.Code(pb.ProblemCode_InvalidEmailAddress):
				return &pb.SignUpResponse{
					Data: &pb.SignUpResponse_Code{
						Code: pb.ProblemCode_InvalidEmailAddress,
					},
					Authorized: false,
				}, nil
			}
		}
		return nil, err
	}

	if _, err := authenticationServer.data.GetContactListDataFromCash(ctx, user.PhoneNo); err == nil {
		return &pb.SignUpResponse{
			Data: &pb.SignUpResponse_Code{
				Code: pb.ProblemCode_UserAlreadyExistWithSameContactNumber,
			},
			Authorized: false,
		}, nil

	}

	if _, err := authenticationServer.data.GetTempContactFromCash(ctx, user.PhoneNo); err == nil {
		return &pb.SignUpResponse{
			Data: &pb.SignUpResponse_Code{
				Code: pb.ProblemCode_UserAlreadyExistWithSameContactNumber,
			},
			Authorized: false,
		}, nil

	}

	userId, err := uuid.NewRandom()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "can not generate internal userId  : %w", err)
	}
	fmt.Println("UUID Generated")

	err = authenticationServer.data.CreateTemporaryUserInCash(ctx, &structs.UserData{
		UserId:   userId.String(),
		Username: user.GetUsername(),
		Password: user.GetPassword(),
		PhoneNo:  user.GetPhoneNo(),
		Email:    user.GetEmail(),
		PinCode:  user.GetPinCode(),
	})
	if err != nil {
		return nil, err
	}

	err = authenticationServer.data.SetTempContactToCash(ctx, user.PhoneNo, userId.String())
	if err != nil {
		return nil, err
	}

	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, userId.String(), false, []int{data_services.GetNewToken, data_services.ResendOTP, data_services.ConformContact, data_services.LogOut})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token", err)
	}

	err = authenticationServer.data.GenerateAndSendOTP(ctx, userId.String(), user.GetPhoneNo(), 0, data_services.Validation5Min)
	if err != nil {
		return nil, err
	}

	return &pb.SignUpResponse{
		Data: &pb.SignUpResponse_ResponseData{
			ResponseData: &pb.ResponseData{
				Token:        authToken,
				RefreshToken: refreshToken,
			},
		},
		Authorized: false,
	}, nil
}

func (authenticationServer *AuthenticationServer) SignInWithMail(ctx context.Context, request *pb.SignInForMailBaseRequest) (*pb.SignInForMailBaseResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	email, err := helpers.SanitizeAndValidateEmailAddress(request.Mail)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Code(pb.ProblemCode_NoEmailIsProvided):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_NoEmailIsProvided,
					},
				}, nil
			case codes.Code(pb.ProblemCode_InvalidEmailAddress):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_InvalidEmailAddress,
					},
				}, nil
			}
		}
	}
	password, err := helpers.SanitizeAndValidatePassword(request.Password)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Code(pb.ProblemCode_NoPasswordIsProvided):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_NoPasswordIsProvided,
					},
				}, nil
			case codes.Code(pb.ProblemCode_InvalidPasswordLength):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_InvalidPasswordLength,
					},
				}, nil
			}
		}
	}
	fmt.Println("Sanitization and validation completed")

	err = helpers.ContextError(ctx)
	if err != nil {
		fmt.Println(err)
	}

	userId, err := authenticationServer.data.SignInWithMailAndPassword(email, password)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Code(pb.ProblemCode_InvalidUserCredentials):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_InvalidUserCredentials,
					},
				}, nil

			case codes.Code(pb.ProblemCode_InvalidPassword):
				return &pb.SignInForMailBaseResponse{
					Data: &pb.SignInForMailBaseResponse_Code{
						Code: pb.ProblemCode_InvalidPassword,
					},
				}, nil

			}
		}
		return nil, status.Errorf(codes.Unknown, "Unable To Authenticate", err)
	}

	fmt.Println("Generating token")

	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, userId, true, []int{data_services.LogOut, data_services.GetNewToken, data_services.External})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token", err)
	}

	fmt.Println("Generated token")

	return &pb.SignInForMailBaseResponse{
		Data: &pb.SignInForMailBaseResponse_ResponseData{
			ResponseData: &pb.ResponseData{
				Token:        authToken,
				RefreshToken: refreshToken,
			},
		},
	}, nil

}

func (authenticationServer *AuthenticationServer) Logout(ctx context.Context, request *pb.LogoutRequest) (*pb.LogoutResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.LogOut)
	if err != nil {
		return &pb.LogoutResponse{Status: false}, err
	}

	err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
	if err != nil {
		return &pb.LogoutResponse{Status: false}, err
	}
	return &pb.LogoutResponse{Status: true}, nil
}

func (authenticationServer *AuthenticationServer) ContactConformation(ctx context.Context, request *pb.ContactConformationRequest) (*pb.ContactConformationResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.ConformContact)
	if err != nil {
		return nil, err
	}

	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Token", err)
	}
	if authorized {
		return nil, status.Errorf(codes.AlreadyExists, "Already Authorized")
	}

	cashVal, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, err
	}

	fmt.Println("Val : ", cashVal)
	fmt.Println("Requested OTP : ", request.GetOtp())

	var val structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(cashVal), &val)

	if val.OTP == request.GetOtp() {

		data, err := authenticationServer.data.GetTemporaryUserFromCash(ctx, token.Audience)
		if err != nil {
			return nil, err
		}

		err = authenticationServer.data.CreateUser(ctx, data)
		if err != nil {
			return nil, err // If User Already Exist Then Report Inconsistency with cash and database
		}

		err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
		if err != nil {
			return nil, err
		}
		fmt.Println("Refresh From Cash Delete ", err)

		err = authenticationServer.data.DelDataFromCash(ctx, token.Audience)
		if err != nil {
			return nil, err
		}
		fmt.Println("Token From Cash Delete ", err)

		err = authenticationServer.data.DelDataFromCash(ctx, data.PhoneNo+"_TEMP_CONTACT")
		if err != nil {
			return nil, err
		}
		fmt.Println("Contact From Cash Delete ", err)

		refreshTok, authTok, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, token.Audience, true, []int{data_services.LogOut, data_services.GetNewToken, data_services.External})
		if err != nil {
			return nil, err
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
		return nil, err
	}

	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Token", err)
	}
	if authorized {
		return nil, status.Errorf(codes.PermissionDenied, "You are not authorized for this service")
	}

	val, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)

	var data structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(val), &data)

	fmt.Println("Data Resend Times : ", data.ResendTimes)
	fmt.Println("Time Of OTP Sending : ", data.Time)
	fmt.Println("Current Time  : ", time.Now())

	// If OTPResponse_Ok then TimeToWaitForNextRequest is time after which you can get *next* otp if required
	// If OTPResponse_NotOk then TimeToWaitForNextRequest is time to wait to get otp.

	switch data.ResendTimes {
	case 0:
		err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 1, data_services.Validation5Min+time.Minute)
		if err != nil {
			return nil, err
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_OK,
			TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation5Min),
		}, nil

	case 1:
		if time.Now().Sub(data.Time) >= data_services.Validation5Min {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 2, data_services.Validation5Min+time.Minute)
			if err != nil {
				return nil, err
			}

			return &pb.ResendOTPResponse{
				Response:                 pb.OTPResponse_OK,
				TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation5Min),
			}, nil
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_NotOk,
			TimeToWaitForNextRequest: ptypes.DurationProto(time.Now().Sub(data.Time)),
		}, nil

	case 2:
		if time.Now().Sub(data.Time) >= data_services.Validation5Min {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 3, data_services.Validation5Min+time.Minute)
			if err != nil {
				return nil, err
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

	case 3:
		if time.Now().Sub(data.Time) >= data_services.Validation10Min {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 4, data_services.Validation10Min+time.Minute)
			if err != nil {
				return nil, err
			}

			return &pb.ResendOTPResponse{
				Response:                 pb.OTPResponse_OK,
				TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation5Hr),
			}, nil
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_NotOk,
			TimeToWaitForNextRequest: ptypes.DurationProto(time.Now().Sub(data.Time)),
		}, nil

	case 4:
		if time.Now().Sub(data.Time) >= data_services.Validation12Hr {
			err = authenticationServer.data.GenerateAndSendOTP(ctx, token.Audience, data.PhoneNo, 4, data_services.Validation12Hr+time.Minute)
			if err != nil {
				return nil, err
			}

			return &pb.ResendOTPResponse{
				Response:                 pb.OTPResponse_OK,
				TimeToWaitForNextRequest: ptypes.DurationProto(data_services.Validation12Hr),
			}, nil
		}

		return &pb.ResendOTPResponse{
			Response:                 pb.OTPResponse_NotOk,
			TimeToWaitForNextRequest: ptypes.DurationProto(time.Now().Sub(data.Time)),
		}, nil

	}
	return nil, status.Errorf(codes.Unknown, "Unable To Process Request")
}

func (authenticationServer *AuthenticationServer) ForgetPassword(ctx context.Context, request *pb.ForgetPasswordRequest) (*pb.ForgetPasswordResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	phoNo, err := helpers.SanitizeAndValidatePhoneNumber(request.GetPhoNo())
	if err != nil {
		return nil, err
	}

	id, err := authenticationServer.data.GetContactListDataFromCash(ctx, phoNo)
	if err != nil {
		return &pb.ForgetPasswordResponse{
			Data: &pb.ForgetPasswordResponse_Code{
				Code: pb.ProblemCode_UserNotExist,
			},
		}, nil
	}
	refreshToken, authToken, err := authenticationServer.data.GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx, id, false, []int{data_services.GetNewToken, data_services.ResendOTP, data_services.ForgetPassword})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable To Generate Refresh Token", err)
	}

	err = authenticationServer.data.GenerateAndSendOTP(ctx, id, phoNo, 0, data_services.Validation5Min)
	if err != nil {
		return nil, err
	}

	return &pb.ForgetPasswordResponse{
		Data: &pb.ForgetPasswordResponse_ResponseData{
			ResponseData: &pb.ResponseData{
				Token:        authToken,
				RefreshToken: refreshToken,
			},
		},
	}, nil
}

func (authenticationServer *AuthenticationServer) ConformForgetPasswordOTP(ctx context.Context, request *pb.ConformForgetPasswordOTPRequest) (*pb.ConformForgetPasswordOTPResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetToken(), os.Getenv("AUTH_TOKEN_SECRETE"), data_services.ForgetPassword)
	if err != nil {
		return nil, err
	}

	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Token", err)
	}
	if authorized {
		return nil, status.Errorf(codes.AlreadyExists, "Invalid Token")
	}

	cashVal, err := authenticationServer.data.GetDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, err
	}

	fmt.Println("Val : ", cashVal)
	fmt.Println("Requested OTP : ", request.GetOtp())

	var val structs.OTPCashData
	structs.UnmarshalOTPCash([]byte(cashVal), &val)

	if val.OTP == request.GetOtp() {

		err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
		if err != nil {
			return nil, err
		}
		fmt.Println("Refresh From Cash Delete ", err)

		err = authenticationServer.data.DelDataFromCash(ctx, token.Audience)
		if err != nil {
			return nil, err
		}
		fmt.Println("Token From Cash Delete ", err)

		passToken, err := authenticationServer.data.GeneratePassTokenAndAddToCash(ctx, token.Audience, []int{data_services.NewPassToken})
		if err != nil {
			return nil, err
		}

		return &pb.ConformForgetPasswordOTPResponse{
			NewPassToken: passToken,
		}, nil

	}

	err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
	if err != nil {
		return nil, err
	}
	fmt.Println("Refresh From Cash Delete ", err)

	err = authenticationServer.data.DelDataFromCash(ctx, token.Audience)
	if err != nil {
		return nil, err
	}
	fmt.Println("Token From Cash Delete ", err)

	return nil, status.Errorf(codes.PermissionDenied, "Invalid OTP To Get Password")

}

func (authenticationServer *AuthenticationServer) SetNewPassword(ctx context.Context, request *pb.SetNewPasswordRequest) (*pb.SetNewPasswordResponse, error) {

	if !helpers.CheckForAPIKey(request.GetApiKey()) {
		return nil, status.Errorf(codes.Unauthenticated, "No API Key Is Specified")
	}

	token, err := authenticationServer.data.ValidateToken(ctx, request.GetNewPassToken(), os.Getenv("PASS_TOKEN_SECRETE"), data_services.NewPassToken)
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, err
	}

	var authorized bool
	if err = token.Get("authorized", &authorized); err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, status.Errorf(codes.InvalidArgument, "Invalid Token", err)
	}
	if !authorized {
		err = authenticationServer.data.DelDataFromCash(ctx, token.Subject)
		if err != nil {
			return &pb.SetNewPasswordResponse{Status: false}, err
		}
		return &pb.SetNewPasswordResponse{Status: false}, status.Errorf(codes.AlreadyExists, "Invalid Token")
	}

	password, err := helpers.SanitizeAndValidatePassword(request.GetNewPassword())
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, err
	}

	err = authenticationServer.data.UpdatePassword(token.Audience, password)
	if err != nil {
		return &pb.SetNewPasswordResponse{Status: false}, err
	}
	return &pb.SetNewPasswordResponse{Status: true}, nil
}
