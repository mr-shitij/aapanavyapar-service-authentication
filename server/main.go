package main

import (
	"aapanavyapar_service_authentication/pb"
	"aapanavyapar_service_authentication/services/authentication_services"
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 0, "the server port")
	flag.Parse()
	log.Printf("Stating server on port  :  %d", *port)

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Fali to load enviromental variables")
	}

	fmt.Println("Environmental Variables Loaded .. !!")

	server, err := authentication_services.NewAuthenticationServer()
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthenticationServer(grpcServer, server)

	address := fmt.Sprintf("0.0.0.0:%d", *port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("Can not start server", err)
	}
	err = grpcServer.Serve(listener)
	if err != nil {
		log.Fatal("Can not start server", err)
	}
}

/*

1.UnaryInterceptor Implementation
2.Polish Code
3.Refresh Token Exchanging Mechanism for future so no need to re-login after some time.


4.Implement Validate Methods for External Service for checking is token is present in cash or not( token validation )
	this only accepts token id and checks if it is present in cash or not and return true or false based on results.
	Solution for this is to decrease the life time of token so that after some time token will automatically dead and so person demand for new token by refresh token but it is expired so auth fails and we success.


*/
