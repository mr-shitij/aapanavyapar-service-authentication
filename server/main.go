package main

import (
	"aapanavyapar_service_authentication/pb"
	"aapanavyapar_service_authentication/services/authentication_services"
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"strconv"
	"time"
)

func main(){
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Fali to load enviromental variables")
	}
	fmt.Println("Environmental Variables Loaded .. !!")

	server, err := authentication_services.NewAuthenticationServer()
	if err != nil {
		panic(err)
	}
	//respUp, err := server.Signup(context.Background(), &pb.SignUpRequest{
	//	Username: "Shitij1",
	//	Password: "1234567881",
	//	PhoneNo:  "1234567998",
	//	Email:    "shitij18@mail.com",
	//	PinCode:  "425107",
	//})
	//
	//if err != nil {
	//	fmt.Println("SignUp Error : ", err)
	//}
	//
	//fmt.Println("SingUp Response Authorized : ", respUp.Authorized)

	//data := respUp.Data
	//switch data.(type) {
	//case *pb.SignUpResponse_ResponseData:
	//	responseData := data.(*pb.SignUpResponse_ResponseData)
	//	fmt.Println("Token Of Signup",responseData.ResponseData.GetToken())
	//	fmt.Println("Refresh Token Of Signup",responseData.ResponseData.GetRefreshToken())
	//
	//	resp,err := server.ContactConformation(context.Background(), &pb.ContactConformationRequest{
	//		Token: responseData.ResponseData.GetToken(),
	//		Otp: "12345",
	//	})
	//
	//	fmt.Println(err)
	//	authentication_services.PrintClaimsOfAuthToken(resp.GetToken())
	//	authentication_services.PrintClaimsOfRefreshToken(resp.GetRefreshToken())
	//
	//	break
	//case *pb.SignUpResponse_Code:
	//	responseData := data.(*pb.SignUpResponse_Code)
	//	fmt.Println("Signup Response Code Data : ", responseData.Code)
	//	break
	//}

	respIn, err := server.SignInWithMail(context.Background(), &pb.SignInForMailBaseRequest{
		Mail:     "shitij18@mail.com",
		Password: "1234567881",
	})

	if err != nil {
		fmt.Println("SignIn Error : ", err)
	}
	fmt.Println("SingIn Response : ", respIn)


	token, err := server.GetNewToken(context.Background(), &pb.NewTokenRequest{RefreshToken: respIn.GetResponseData().GetRefreshToken()})
	if err != nil {
		panic(err)
	}
	authentication_services.PrintClaimsOfAuthToken(token.GetToken())

	for i:=0; i<=5; i++ {
		otpResponse, err := server.ResendOTP(context.Background(), &pb.ResendOTPRequest{Token: token.GetToken()})
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(strconv.Itoa(i) + " : Time To Wait : ", otpResponse.TimeToWaitForNextRequest.String())
		fmt.Println(strconv.Itoa(i) + " : Response Of OTP : ", otpResponse.Response.String())
		time.Sleep(otpResponse.TimeToWaitForNextRequest.AsDuration())
		respOut, err := server.Logout(context.Background(), &pb.LogoutRequest{Token: token.GetToken()})
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("LogOut Response : ", respOut)
	}
}
