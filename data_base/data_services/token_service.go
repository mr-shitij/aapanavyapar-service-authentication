package data_services

import (
	"aapanavyapar_service_authentication/data_base/helpers"
	"aapanavyapar_service_authentication/data_base/structs"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/o1egl/paseto/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"time"
)

const (
	MaxTokenAttempt    = 12
	RefreshTokenExpiry = 366 * time.Hour // 2 weeks
	AuthTokenExpiry    = 24  * time.Hour // 1 day
)

func (dataService *DataServices) GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx context.Context, userId string, authorized bool) (string, string, error) {
	now := time.Now()
	exp := now.Add(RefreshTokenExpiry) // Two Weeks
	nbt := now


	refreshTokenId, err := uuid.NewRandom()
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "can not generate internal uuid  : %w", err)
	}

	jsonToken := paseto.JSONToken{
		Audience:   userId,
		Subject: 	refreshTokenId.String(),
		Issuer:     os.Getenv("TOKEN_ISSUER"),
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	jsonToken.Set("authorized", authorized)
	footer := "Powered By AapanaVypar"

	// Encrypt data
	token, err := paseto.Encrypt([]byte(os.Getenv("REFRESH_TOKEN_SECRETE")), jsonToken, footer)

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to encrypt token  : %w", err)
	}

	cashData := structs.RefreshTokenCashData{
		RefreshToken:   token,
		AllocatedToken: 0,
	}
	err = dataService.Cash.Set(ctx, refreshTokenId.String(),
		cashData.Marshal(), RefreshTokenExpiry).Err()

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to add token to cash  : %w", err)
	}

	authToken, err := GenerateAuthToken(userId, refreshTokenId.String(), authorized)

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to create auth token  : %w", err)
	}

	return token, authToken, nil
}


func (dataService *DataServices) ValidateRefreshTokenAndGenerateNewAuthToken(ctx context.Context, tokenString string) (bool, string, error) {

	receivedRefreshToken, err := dataService.ValidateToken(ctx, tokenString, os.Getenv("REFRESH_TOKEN_SECRETE"))
	if err != nil {
		return false, "", err
	}


	val, err := dataService.Cash.Get(ctx, receivedRefreshToken.Subject).Result()

	switch {
		case err == redis.Nil:
			return false, "", status.Errorf(codes.NotFound, "Token Not Exist %v", err)
		case err != nil:
			return false, "", status.Errorf(codes.Internal, "Unable To Fetch Value %v", err)
		case val == "":
			return false, "", status.Errorf(codes.Unknown, "Empty Value %v", err)
	}

	var cashData structs.RefreshTokenCashData
	structs.UnmarshalTokenCash([]byte(val), &cashData)

	fmt.Println(cashData)

	if cashData.AllocatedToken > MaxTokenAttempt || cashData.RefreshToken != tokenString {
		return false, "", status.Errorf(codes.ResourceExhausted, "Refresh Token Is Reach To Its Limit %v", err)
	}

	if err := helpers.ContextError(ctx); err != nil {
		return false, "", err
	}


	var authorized bool
	err = receivedRefreshToken.Get("authorized", &authorized)
	fmt.Println("authorized  : ", authorized)
	if err != nil {
		return false, "", status.Errorf(codes.PermissionDenied, "Token Is Not Valid %v", err)
	}

	// Note Update Cash When the user validates his contact number
	//
	//if !authorized {
	//	authorized, err = dataService.IsUserAuthorized(receivedRefreshToken.Audience)
	//	if err != nil {
	//		return false, "", status.Errorf(codes.Internal, "Error while authorizing token %v", err)
	//	}
	//}


	token, err := GenerateAuthToken(receivedRefreshToken.Audience, receivedRefreshToken.Subject, authorized)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "Unable To Create The Token %v", err)
	}

	tokenCashData := structs.RefreshTokenCashData{
		RefreshToken:   cashData.RefreshToken,
		AllocatedToken: cashData.AllocatedToken + 1,
	}
	err = dataService.Cash.Set(ctx, receivedRefreshToken.Subject,
		tokenCashData.Marshal(), RefreshTokenExpiry).Err()

	if err != nil {
		return false, "", status.Errorf(codes.Internal, "unable to add token to cash  : %w", err)
	}

	return true, token, nil
}



func GenerateAuthToken(userId string, refreshTokenId string, authorized bool) (string, error) {

	now := time.Now()
	exp := now.Add(AuthTokenExpiry) // One Day
	nbt := now

	jsonToken := paseto.JSONToken{
		Audience:   userId,
		Subject:    refreshTokenId,
		Issuer:     os.Getenv("TOKEN_ISSUER"),
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	jsonToken.Set("authorized", authorized)
	footer := "Powered By AapanaVypar"

	// Encrypt data
	token, err := paseto.Encrypt([]byte(os.Getenv("AUTH_TOKEN_SECRETE")), jsonToken, footer)

	if err != nil {
		return "", err
	}
	return token, nil
}

func (dataService *DataServices) ValidateToken(ctx context.Context, tokenString, key string) (*paseto.JSONToken, error) {
	var receivedToken paseto.JSONToken
	var newFooter string
	err := paseto.Decrypt(tokenString, []byte(key), &receivedToken, &newFooter)

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Token %v", err)
	}

	err = receivedToken.Validate(
		paseto.ValidAt(time.Now()),
		paseto.IssuedBy(os.Getenv("TOKEN_ISSUER")),
	)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "Invalid Token %v", err)
	}

	_, err = uuid.Parse(receivedToken.Subject)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Argument ", err)
	}


	val, err := dataService.Cash.Get(ctx, receivedToken.Subject).Result()

	switch {
	case err == redis.Nil:
		return nil, status.Errorf(codes.NotFound, "Token Not Exist %v", err)
	case err != nil:
		return nil, status.Errorf(codes.Internal, "Unable To Fetch Value %v", err)
	case val == "":
		return nil, status.Errorf(codes.Unknown, "Empty Value %v", err)
	}


	_, err = uuid.Parse(receivedToken.Audience)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Argument ", err)
	}
	return &receivedToken, nil
}
