package data_services

import (
	"aapanavyapar_service_authentication/data-base/helpers"
	"aapanavyapar_service_authentication/data-base/structs"
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

	PassTokenExpiry = time.Minute * 5
)

func GenerateRefreshToken(userId string, userName string, authorized bool, accessGroup []int) (string, string, error) {

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
		Jti:        refreshTokenId.String(),
		Subject:    userName,
		Issuer:     os.Getenv("TOKEN_ISSUER"),
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	jsonToken.Set("authorized", authorized)
	jsonToken.Set("accessGroup", accessGroup)
	footer := "Powered By AapanaVypar"

	// Encrypt data
	token, err := paseto.Encrypt([]byte(os.Getenv("REFRESH_TOKEN_SECRETE")), jsonToken, footer)

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to encrypt token  : %w", err)
	}

	return token, refreshTokenId.String(), nil
}

func GeneratePassToken(userId string, accessGroup []int) (string, string, error) {

	now := time.Now()
	exp := now.Add(PassTokenExpiry)
	nbt := now

	passTokenId, err := uuid.NewRandom()
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "can not generate internal uuid  : %w", err)
	}

	jsonToken := paseto.JSONToken{
		Audience:   userId,
		Jti:        passTokenId.String(),
		Issuer:     os.Getenv("TOKEN_ISSUER"),
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	jsonToken.Set("accessGroup", accessGroup)
	footer := "Powered By AapanaVypar"

	// Encrypt data
	token, err := paseto.Encrypt([]byte(os.Getenv("PASS_TOKEN_SECRETE")), jsonToken, footer)

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to encrypt token  : %w", err)
	}

	return token, passTokenId.String(), nil
}

func (dataService *DataServices) GenerateRefreshAndAuthTokenAndAddRefreshToCash(ctx context.Context, userId string, userName string, authorized bool, accessGroup []int) (string, string, error) {

	token, refreshTokenId, err := GenerateRefreshToken(userId, userName, authorized, accessGroup)

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

	authToken, err := GenerateAuthToken(userId, userName, refreshTokenId, authorized, accessGroup)

	if err != nil {
		return "", "", status.Errorf(codes.Internal, "unable to create auth token  : %w", err)
	}

	return token, authToken, nil
}

func (dataService *DataServices) GeneratePassTokenAndAddToCash(ctx context.Context, userId string, accessGroup []int) (string, error) {

	token, passTokenId, err := GeneratePassToken(userId, accessGroup)
	if err != nil {
		return "", err
	}

	cashData := structs.RefreshTokenCashData{
		RefreshToken:   token,
		AllocatedToken: 0,
	}

	err = dataService.SetDataToCash(ctx, passTokenId, cashData.Marshal(), PassTokenExpiry)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (dataService *DataServices) ValidateRefreshTokenAndGenerateNewAuthToken(ctx context.Context, tokenString string, receivedRefreshToken *paseto.JSONToken) (bool, string, error) {

	val, err := dataService.GetDataFromCash(ctx, receivedRefreshToken.Jti)
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

	var accessGroup []int
	err = receivedRefreshToken.Get("accessGroup", &accessGroup)
	fmt.Println("Access Group  : ", accessGroup)
	if err != nil {
		return false, "", status.Errorf(codes.PermissionDenied, "Token Is Not Valid %v", err)
	}

	token, err := GenerateAuthToken(receivedRefreshToken.Audience, receivedRefreshToken.Subject, receivedRefreshToken.Jti, authorized, accessGroup)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "Unable To Create The Token %v", err)
	}

	tokenCashData := structs.RefreshTokenCashData{
		RefreshToken:   cashData.RefreshToken,
		AllocatedToken: cashData.AllocatedToken + 1,
	}

	if authorized {
		err = dataService.SetDataToCash(ctx, receivedRefreshToken.Jti,
			tokenCashData.Marshal(), RefreshTokenExpiry)
	} else {
		err = dataService.SetDataToCash(ctx, receivedRefreshToken.Jti,
			tokenCashData.Marshal(), RefreshTokenExpiryForUnAuthorized)
	}

	if err != nil {
		return false, "", err
	}

	return true, token, nil
}

func GenerateAuthToken(userId string, userName string, refreshTokenId string, authorized bool, accessGroup []int) (string, error) {

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
		Jti:        refreshTokenId,
		Subject:    userName,
		Issuer:     os.Getenv("TOKEN_ISSUER"),
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	jsonToken.Set("authorized", authorized)
	jsonToken.Set("accessGroup", accessGroup)
	footer := "Powered By AapanaVypar"

	// Encrypt data
	token, err := paseto.Encrypt([]byte(os.Getenv("AUTH_TOKEN_SECRETE")), jsonToken, footer)

	if err != nil {
		return "", err
	}
	return token, nil
}

func (dataService *DataServices) ValidateToken(ctx context.Context, tokenString, key string, access int) (*paseto.JSONToken, error) {
	var receivedToken paseto.JSONToken
	var newFooter string

	fmt.Println("Decrypting Token")
	err := paseto.Decrypt(tokenString, []byte(key), &receivedToken, &newFooter)

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Token %v", err)
	}

	fmt.Println("Validating Token")
	err = receivedToken.Validate(
		paseto.ValidAt(time.Now()),
		paseto.IssuedBy(os.Getenv("TOKEN_ISSUER")),
	)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "Invalid Token %v", err)
	}

	fmt.Println("Checking Access Group For Token")
	var accessGroup []int
	err = receivedToken.Get("accessGroup", &accessGroup)
	fmt.Println("Access Group  : ", accessGroup)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "Token Is Not Valid %v", err)
	}

	if !IsHasAccessTo(accessGroup, access) {
		return nil, status.Errorf(codes.PermissionDenied, "Token Does Not Have Valid Permission To Access Resources %v", err)
	}

	fmt.Println("Checking Refresh Token ID Token")
	_, err = uuid.Parse(receivedToken.Jti)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Argument ", err)
	}

	fmt.Println("Checking Token In Cash Token For Normal")
	_, err = dataService.GetDataFromCash(ctx, receivedToken.Jti)
	if err != nil {
		fmt.Println("Checking Token In Cash Token : ", err)
		return nil, err
	}

	fmt.Println("Checking User UUID Of Token")
	_, err = uuid.Parse(receivedToken.Audience)
	if err != nil {
		fmt.Println("Checking User UUID Of Token : ", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid Argument ", err)
	}

	fmt.Println("Done With Token")
	return &receivedToken, nil
}
