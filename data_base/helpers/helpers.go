package helpers

import (
	"aapanavyapar_service_authentication/pb"
	"context"
	"encoding/base64"
	"github.com/microcosm-cc/bluemonday"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"regexp"
	"strings"
)

func ContextError(ctx context.Context) error {

	switch ctx.Err() {
	case context.Canceled:
		log.Println("Request Canceled")
		return status.Error(codes.DeadlineExceeded, "Request Canceled")
	case context.DeadlineExceeded:
		log.Println("DeadLine Exceeded")
		return status.Error(codes.DeadlineExceeded, "DeadLine Exceeded")
	default:
		return nil
	}
}

func SanitizeAndValidateUserName(userName string) (string, error) {
	p := bluemonday.UGCPolicy()
	userName = p.Sanitize(strings.TrimSpace(userName))
	if userName == "" {
		return "", status.Error(codes.Code(pb.ProblemCode_NoUserNameIsProvided), "User Name Should Not Be Empty")
	}
	return userName, nil
}

func SanitizeAndValidateEmailAddress(email string) (string, error) {
	p := bluemonday.UGCPolicy()
	email = p.Sanitize(strings.TrimSpace(email))
	if email != "" {
		if check, _ := regexp.MatchString("^(([^<>()[\\]\\\\.,;:\\s@\"]+(\\.[^<>()[\\]\\\\.,;:\\s@\"]+)*)|(\".+\"))@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$", email); !check {
			return "", status.Error(codes.Code(pb.ProblemCode_InvalidEmailAddress), "Invalid Email")
		}
		return email, nil
	}
	return "", status.Error(codes.Code(pb.ProblemCode_NoEmailIsProvided), "Email Address Is Empty")
}
func SanitizeAndValidatePhoneNumber(phoneNumber string) (string, error) {
	p := bluemonday.UGCPolicy()
	phoneNumber = p.Sanitize(strings.TrimSpace(phoneNumber))
	if phoneNumber != "" {
		if check, _ := regexp.MatchString("^+[0-9]{10}$", phoneNumber); !check || (len(phoneNumber) <= 1 || len(phoneNumber) > 10) {
			return "", status.Error(codes.Code(pb.ProblemCode_InvalidPhoneNumber), "Invalid Phone Number")
		}
		return phoneNumber, nil
	}
	return "", status.Error(codes.Code(pb.ProblemCode_NoPhoneNumberIsProvided), "Phone Number  Is Empty")
}
func SanitizeAndValidatePinCode(pinCode string) (string, error) {
	p := bluemonday.UGCPolicy()
	pinCode = p.Sanitize(strings.TrimSpace(pinCode))
	if pinCode != "" {
		if check, _ := regexp.MatchString("^[1-9][0-9]{5}$", pinCode); !check {
			return "", status.Error(codes.Code(pb.ProblemCode_InvalidPinCode), "Invalid PinCode")
		}
		return pinCode, nil
	}
	return "", status.Error(codes.Code(pb.ProblemCode_NoPinCodeIsProvided), "pin Code Is Empty")
}
func SanitizeAndValidatePassword(password string) (string, error) {
	if password != "" {
		if len(password) < 8 {
			return "", status.Error(codes.Code(pb.ProblemCode_InvalidPasswordLength), "Invalid Password Length")
		}
		return password, nil
	}
	return "", status.Error(codes.Code(pb.ProblemCode_NoPasswordIsProvided), "Password Is Empty")
}

func SanitizeAndValidate(user *pb.SignUpRequest) (*pb.SignUpRequest, error) {

	var err error
	if user.Username, err = SanitizeAndValidateUserName(user.Username); err != nil {
		return nil, err
	}
	if user.Email, err = SanitizeAndValidateEmailAddress(user.Email); err != nil {
		if e, ok := status.FromError(err); ok && e.Code() != codes.Code(pb.ProblemCode_NoEmailIsProvided) {
			return nil, err
		}
	}

	if user.PhoneNo, err = SanitizeAndValidatePhoneNumber(user.PhoneNo); err != nil {
		return nil, err
	}
	if user.Password, err = SanitizeAndValidatePassword(user.Password); err != nil {
		return nil, err
	}
	if user.PinCode, err = SanitizeAndValidatePinCode(user.PinCode); err != nil {
		return nil, err
	}

	return &pb.SignUpRequest{
		Username: user.Username,
		Password: user.Password,
		PhoneNo:  user.PhoneNo,
		Email:    user.Email,
		PinCode:  user.PinCode,
	}, nil
}

func EncodePhoneNo(phoNo string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(phoNo))
	return sEnc
}

func DecodePhoneNo(message string) (string, error) {
	sDec, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", status.Errorf(codes.Internal, "Unable To Decode Phone No", err)
	}
	return string(sDec), nil
}
