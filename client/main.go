package main

import (
	"aapanavyapar_service_authentication/pb"
	"aapanavyapar_service_authentication/services/authentication_services"
	"context"
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"log"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Fali to load enviromental variables")
	}

	serverAddress := flag.String("address", "", "the server address")
	flag.Parse()
	log.Printf("dialing to server  : %s", *serverAddress)

	conn, err := grpc.Dial(*serverAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatal("Cannot dial server ", err)
	}

	server := pb.NewAuthenticationClient(conn)

	respSignup, err := server.Signup(context.Background(), &pb.SignUpRequest{
		Username: "Shitij1",
		Password: "1234567881",
		PhoneNo:  "1234567998",
		Email:    "shitij18@mail.com",
		PinCode:  "425107",
	})

	if err != nil {
		panic(err)
	}

	switch respSignup.Data.(type) {
	case *pb.SignUpResponse_ResponseData:
		responseData := respSignup.Data.(*pb.SignUpResponse_ResponseData)

		fmt.Println("Token Of Signup : ")
		authentication_services.PrintClaimsOfAuthToken(responseData.ResponseData.GetToken())

		fmt.Println("Refresh Token Of Signup : ")
		authentication_services.PrintClaimsOfRefreshToken(responseData.ResponseData.GetRefreshToken())

		respContactConform, err := server.ContactConformation(context.Background(), &pb.ContactConformationRequest{
			Token: responseData.ResponseData.GetToken(),
			Otp:   "12345",
		})

		if err != nil {
			panic(err)
		}

		fmt.Println("Contact Conform Auth Token Of Signup : ")
		authentication_services.PrintClaimsOfAuthToken(respContactConform.GetToken())
		fmt.Println("Contact Conform Refresh Token Of Signup : ")
		authentication_services.PrintClaimsOfRefreshToken(respContactConform.GetRefreshToken())

		break
	case *pb.SignUpResponse_Code:
		responseData := respSignup.Data.(*pb.SignUpResponse_Code)
		fmt.Println("Signup Response Code Data : ", responseData.Code)
		break
	}

	respIn, err := server.SignInWithMail(context.Background(), &pb.SignInForMailBaseRequest{
		Mail:     "shitij18@mail.com",
		Password: "1234567881",
	})

	if err != nil {
		panic(err)
	}
	fmt.Println("SingIn Response : ")

	authentication_services.PrintClaimsOfAuthToken(respIn.GetResponseData().GetToken())
	authentication_services.PrintClaimsOfRefreshToken(respIn.GetResponseData().GetRefreshToken())

}

//token, err := server.GetNewToken(context.Background(), &pb.NewTokenRequest{RefreshToken: respIn.GetResponseData().GetRefreshToken()})
//if err != nil {
//	panic(err)
//}
//authentication_services.PrintClaimsOfAuthToken(token.GetToken())

//for i:=0; i<=5; i++ {
//	otpResponse, err := server.ResendOTP(context.Background(), &pb.ResendOTPRequest{Token: token.GetToken()})
//	if err != nil {
//		fmt.Println(err)
//	}
//	fmt.Println(strconv.Itoa(i) + " : Time To Wait : ", otpResponse.TimeToWaitForNextRequest.String())
//	fmt.Println(strconv.Itoa(i) + " : Response Of OTP : ", otpResponse.Response.String())
//	time.Sleep(otpResponse.TimeToWaitForNextRequest.AsDuration())
//	respOut, err := server.Logout(context.Background(), &pb.LogoutRequest{Token: token.GetToken()})
//	if err != nil {
//		fmt.Println(err)
//	}
//	fmt.Println("LogOut Response : ", respOut)
//}
//

//respForgot, err := server.ForgetPassword(context.Background(), &pb.ForgetPasswordRequest{PhoNo: "1234567998"})
//if err != nil {
//	panic(err)
//}
//switch respForgot.Data.(type) {
//case *pb.ForgetPasswordResponse_ResponseData:
//	responseDataForget := respForgot.Data.(*pb.ForgetPasswordResponse_ResponseData)
//	authentication_services.PrintClaimsOfAuthToken(responseDataForget.ResponseData.GetToken())
//	authentication_services.PrintClaimsOfRefreshToken(responseDataForget.ResponseData.GetRefreshToken())
//
//	passToken, err := server.ConformForgetPasswordOTP(context.Background(), &pb.ConformForgetPasswordOTPRequest{
//		Otp:   "12345",
//		Token: responseDataForget.ResponseData.GetToken(),
//	})
//
//	if err != nil {
//		panic(err)
//	}
//
//	newPassResp, err := server.SetNewPassword(context.Background(), &pb.SetNewPasswordRequest{
//		NewPassToken: passToken.GetNewPassToken(),
//		NewPassword:  "JaiShriram",
//	})
//
//	fmt.Println("New Pass Error : ", err)
//	fmt.Println("New Pass Resp : ", newPassResp)
//
//
//	respIn, err := server.SignInWithMail(context.Background(), &pb.SignInForMailBaseRequest{
//		Mail:     "shitij18@mail.com",
//		Password: "JaiShriram",
//	})
//
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println("SingIn Response : ", respIn)
//
//
//	authentication_services.PrintClaimsOfAuthToken(respIn.GetResponseData().GetToken())
//	authentication_services.PrintClaimsOfRefreshToken(respIn.GetResponseData().GetRefreshToken())
//
//
//	break
//case *pb.ForgetPasswordResponse_Code:
//	responseData := respForgot.Data.(*pb.ForgetPasswordResponse_Code)
//	fmt.Println("Signup Response Code Data : ", responseData.Code)
//	break
//}

//db := data_services.NewDbConnection()
//err = db.LoadUserContactDataInCash(context.Background())
//if err != nil {
//	panic(err)
//}
//
//
//err = db.SetContactListDataToCash(context.Background(),"1234567948", "tem@mail.com")
//if err != nil {
//	fmt.Println("Adduser : ", err)
//}
//
//
//data, err := db.GetContactListDataFormCash(context.Background(), "1234567948")
//if err != nil {
//	fmt.Println("Get User : ", err)
//}
//fmt.Println("phone : ", data)
//
//
//err = db.DelUserContactDataFromCash(context.Background(), "123567948")
//if err != nil {
//	fmt.Println("Del User : ", err)
//}
//
//
//data, err = db.GetContactListDataFormCash(context.Background(), "1234567998")
//if err != nil {
//	fmt.Println("Get User : ", err)
//}
//fmt.Println("phone : ", data)
//
//err = db.CreateTemporaryUserInCash(context.Background(), &structs.UserData{
//	UserId:   "123",
//	Username: "abc",
//	Password: "pqr",
//	PhoneNo:  "1234567890",
//	Email:    "asda@asad.com",
//	PinCode:  "432156",
//})
//if err != nil {
//	fmt.Println("Create Temp User : ", err)
//}
//
//user, err := db.GetTemporaryUserFromCash(context.Background(), "123")
//if err != nil {
//	fmt.Println("Get Temp User : ", err)
//}
//fmt.Println("Get Temp User : ", user)
