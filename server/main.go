package main

import (
	"aapanavyapar_service_authentication/pb"
	"aapanavyapar_service_authentication/services/authentication_services"
	"context"
	"fmt"
	"github.com/joho/godotenv"
	"log"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Fali to load enviromental variables")
	}
	fmt.Println("Environmental Variables Loaded .. !!")

	server, err := authentication_services.NewAuthenticationServer()
	if err != nil {
		panic(err)
	}
	respUp, err := server.Signup(context.Background(), &pb.SignUpRequest{
		Username: "Shitij1",
		Password: "1234567881",
		PhoneNo:  "1234567998",
		Email:    "shitij18@mail.com",
		PinCode:  "425107",
	})

	if err != nil {
		fmt.Println("SignUp Error : ", err)
	}

	fmt.Println("SingUp Response Authorized : ", respUp.Authorized)

	data := respUp.Data
	switch data.(type) {
	case *pb.SignUpResponse_ResponseData:
		responseData := data.(*pb.SignUpResponse_ResponseData)
		fmt.Println("Token Of Signup", responseData.ResponseData.GetToken())
		fmt.Println("Refresh Token Of Signup", responseData.ResponseData.GetRefreshToken())

		resp, err := server.ContactConformation(context.Background(), &pb.ContactConformationRequest{
			Token: responseData.ResponseData.GetToken(),
			Otp:   "12345",
		})

		fmt.Println(err)
		authentication_services.PrintClaimsOfAuthToken(resp.GetToken())
		authentication_services.PrintClaimsOfRefreshToken(resp.GetRefreshToken())

		break
	case *pb.SignUpResponse_Code:
		responseData := data.(*pb.SignUpResponse_Code)
		fmt.Println("Signup Response Code Data : ", responseData.Code)
		break
	}

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
}

/*

0. Forgot Password Implementation

1.UnaryInterceptor Implementation
2.Polish Code
3.Refresh Token Exchanging Mechanism for future so no need to re-login after some time.


4.Implement Validate Methods for External Service for checking is token is present in cash or not( token validation )
	this only accepts token id and checks if it is present in cash or not and return true or false based on results.
	Solution for this is to decrease the life time of token so that after some time token will automatically dead and so person demand for new token by refresh token but it is expired so auth fails and we success.


*/
