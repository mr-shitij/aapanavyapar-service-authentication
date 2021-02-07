package data_services

import (
	"aapanavyapar_service_authentication/data_base/structs"
	"context"
	"crypto/rand"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"os"
	"strconv"
	"time"
)

const (
	Validation5Min  = time.Minute * 5
	Validation10Min = time.Minute * 10
	Validation5Hr   = time.Hour * 5
	Validation12Hr  = time.Hour * 12
)

func (dataService *DataServices) GenerateAndSendOTP(ctx context.Context, userId string, phoneNo string, resendTime int32, validTime time.Duration) error {
	otp := GenerateOTP()
	fmt.Println("Sending The Generated OTP : "+otp+" to : ", phoneNo)
	data := &structs.OTPCashData{
		OTP:         otp,
		PhoneNo:     phoneNo,
		ResendTimes: resendTime,
		Time:        time.Now(),
	}
	err := dataService.SetDataToCash(ctx, userId, data.Marshal(), validTime)
	if err != nil {
		return status.Errorf(codes.Internal, "Unable To Cash OTP", err)
	}
	return nil
}

func GenerateOTP() string {

	max, _ := strconv.Atoi(os.Getenv("OTP_LENGTH"))

	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		fmt.Println("Unable To Generate OTP ", err)
		return "123456"
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
