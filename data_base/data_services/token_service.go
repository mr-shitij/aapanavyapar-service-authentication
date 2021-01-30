package data_services

import (
	"aapanavyapar_service_authentication/data_base/helpers"
	"aapanavyapar_service_authentication/data_base/structs"
	"context"
	"fmt"
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
	AuthTokenExpiry    = 24 * time.Hour  // 1 day

	MaxTokenAttemptForUnAuthorized    = 7
	RefreshTokenExpiryForUnAuthorized = time.Minute * 30 // 1/2 hours
	AuthTokenExpiryForUnAuthorized    = time.Minute * 5  // 5 minutes
)

func GenerateRefreshToken(userId string, authorized bool) (string, string, error) {

	now := time.Now()

	var exp time.Time
	if authorized {
		exp = now.Add(RefreshTokenExpiry)
	} else {
		exp = now.Add(RefreshTokenExpiryForUnAuthorized)
	}
	nbt := now

	refreshTokenId, err := uuid.NewRandom()
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "can not generate internal uuid  : %w", err)
	}

	jsonToken := paseto.JSONToken{
		Audience:   userId,
		Subject:    refreshTokenId.String(),
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

	return token, refreshTokenId.String(), nil
}

func (dataService *DataServices) GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx context.Context, userId string, authorized bool) (string, string, error) {

	token, refreshTokenId, err := GenerateRefreshToken(userId, authorized)

	cashData := structs.RefreshTokenCashData{
		RefreshToken:   token,
		AllocatedToken: 0,
	}

	if authorized {
		err = dataService.SetDataToCash(ctx, refreshTokenId, cashData.Marshal(), RefreshTokenExpiry)
	} else {
		err = dataService.SetDataToCash(ctx, refreshTokenId, cashData.Marshal(), RefreshTokenExpiryForUnAuthorized)
	}

	if err != nil {
		return "", "", err
	}

	authToken, err := GenerateAuthToken(userId, refreshTokenId, authorized)

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

	val, err := dataService.GetDataFormCash(ctx, receivedRefreshToken.Subject)
	if err != nil {
		return false, "", err
	}

	var cashData structs.RefreshTokenCashData
	structs.UnmarshalTokenCash([]byte(val), &cashData)

	fmt.Println(cashData)

	var authorized bool
	err = receivedRefreshToken.Get("authorized", &authorized)
	fmt.Println("authorized  : ", authorized)
	if err != nil {
		return false, "", status.Errorf(codes.PermissionDenied, "Token Is Not Valid %v", err)
	}

	if ((authorized && cashData.AllocatedToken > MaxTokenAttempt) || (!authorized && cashData.AllocatedToken > MaxTokenAttemptForUnAuthorized)) || cashData.RefreshToken != tokenString {
		return false, "", status.Errorf(codes.ResourceExhausted, "Refresh Token Is Reach To Its Limit %v", err)
	}

	if err := helpers.ContextError(ctx); err != nil {
		return false, "", err
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

	if authorized {
		err = dataService.SetDataToCash(ctx, receivedRefreshToken.Subject,
			tokenCashData.Marshal(), RefreshTokenExpiry)
	} else {
		err = dataService.SetDataToCash(ctx, receivedRefreshToken.Subject,
			tokenCashData.Marshal(), RefreshTokenExpiryForUnAuthorized)
	}

	if err != nil {
		return false, "", err
	}

	return true, token, nil
}

func GenerateAuthToken(userId string, refreshTokenId string, authorized bool) (string, error) {

	now := time.Now()
	var exp time.Time
	if authorized {
		exp = now.Add(AuthTokenExpiry)
	} else {
		exp = now.Add(AuthTokenExpiryForUnAuthorized)
	}
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

	_, err = dataService.GetDataFormCash(ctx, receivedToken.Subject)
	if err != nil {
		return nil, err
	}

	_, err = uuid.Parse(receivedToken.Audience)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Argument ", err)
	}

	return &receivedToken, nil
}
