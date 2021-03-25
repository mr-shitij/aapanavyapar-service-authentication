package data_services

import (
	"aapanavyapar_service_authentication/data_base/helpers"
	"aapanavyapar_service_authentication/data_base/structs"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

const TemporaryUserDetailsCashTiming = time.Minute * 30

func (dataService *DataServices) LoadUserContactDataInCash(ctx context.Context) error {

	rows, err := dataService.GetPhoneDetails()
	if err != nil {
		return err
	}

	for rows.Next() {
		detail := structs.UserContactDetails{}
		err := rows.StructScan(&detail)
		if err != nil {
			return status.Errorf(codes.Internal, "Unable To Structure Data : ", err)
		}

		err = dataService.SetContactListDataToCash(ctx, detail.PhoneNo, detail.UserId)
		if err != nil {
			return err
		}

		fmt.Println("Data : ", detail)

	}

	return nil
}

func (dataService *DataServices) CreateTemporaryUserInCash(ctx context.Context, data *structs.UserData) error {

	err := dataService.SetDataToCash(ctx, data.UserId+"_Temp", data.Marshal(), TemporaryUserDetailsCashTiming)
	if err != nil {
		return err
	}

	return nil
}

func (dataService *DataServices) GetTemporaryUserFromCash(ctx context.Context, id string) (*structs.UserData, error) {

	val, err := dataService.GetDataFromCash(ctx, id+"_Temp")
	if err != nil {
		return nil, err
	}

	data := structs.UserData{}
	structs.UnmarshalUserDataCash([]byte(val), &data)

	return &data, nil
}

func (dataService *DataServices) DelTemporaryUserFromCash(ctx context.Context, id string) error {

	err := dataService.DelDataFromCash(ctx, id+"_Temp")
	if err != nil {
		return err
	}
	return nil

}

func (dataService *DataServices) GetContactListDataFromCash(ctx context.Context, phoNo string) (string, error) {

	phoNo = helpers.EncodePhoneNo(phoNo)
	val, err := dataService.GetHashDataFromCash(ctx, "contact", phoNo)

	val, err = helpers.DecodePhoneNo(val)
	if err != nil {
		return "", err
	}

	if val == "" {
		return "", status.Errorf(codes.NotFound, "No Data Found")
	}

	return val, nil
}

func (dataService *DataServices) SetContactListDataToCash(ctx context.Context, key string, value interface{}) error {

	value = helpers.EncodePhoneNo(value.(string))
	key = helpers.EncodePhoneNo(key)
	err := dataService.SetHashDataToCash(ctx, "contact", key, value)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to add contact to hash in cash  : %w", err)
	}

	return nil
}

func (dataService *DataServices) GetTempContactFromCash(ctx context.Context, phoNo string) (string, error) {

	phoNo = helpers.EncodePhoneNo(phoNo)
	val, err := dataService.GetDataFromCash(ctx, phoNo+"_TEMP_CONTACT")

	val, err = helpers.DecodePhoneNo(val)
	if err != nil {
		return "", err
	}

	if val == "" {
		return "", status.Errorf(codes.NotFound, "No Data Found")
	}

	return val, nil
}

func (dataService *DataServices) SetTempContactToCash(ctx context.Context, key string, value interface{}) error {

	value = helpers.EncodePhoneNo(value.(string))
	key = helpers.EncodePhoneNo(key)
	err := dataService.SetDataToCash(ctx, key+"_TEMP_CONTACT", value, TemporaryUserDetailsCashTiming)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to add temp contact in cash  : %w", err)
	}

	return nil
}

func (dataService *DataServices) DelTempContactFromCash(ctx context.Context, key string) error {

	err := dataService.DelDataFromCash(ctx, key+"_TEMP_CONTACT")
	if err != nil {
		return err
	}

	return nil
}

func (dataService *DataServices) DelUserContactDataFromCash(ctx context.Context, phoNo string) error {

	err := dataService.DelHashDataFromCash(ctx, "contact", phoNo)
	if err != nil {
		return err
	}
	return nil
}

func (dataService *DataServices) GetHashDataFromCash(ctx context.Context, hashId string, key string) (string, error) {

	val, err := dataService.Cash.HGet(ctx, hashId, key).Result()
	switch {
	case err == redis.Nil:
		return "", status.Errorf(codes.NotFound, "Value Not Exist %v", err)
	case err != nil:
		return "", status.Errorf(codes.Internal, "Unable To Fetch Value %v", err)
	case val == "":
		return "", status.Errorf(codes.Unknown, "Empty Value %v", err)
	}
	return val, err
}

func (dataService *DataServices) SetHashDataToCash(ctx context.Context, hashId string, key string, value interface{}) error {

	err := dataService.Cash.HSet(ctx, hashId, key, value).Err()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to add data to hash of cash  : %w", err)
	}
	return nil
}

func (dataService *DataServices) DelHashDataFromCash(ctx context.Context, hashId string, key string) error {

	err := dataService.Cash.HDel(ctx, hashId, key).Err()
	if err != nil {
		return status.Errorf(codes.Unknown, "Unable To Delete Data From Hash Of Cash", err)
	}
	return nil
}

func (dataService *DataServices) GetDataFromCash(ctx context.Context, key string) (string, error) {

	fmt.Println("Searching Data For : " + key + " in cash")

	val, err := dataService.Cash.Get(ctx, key).Result()

	switch {
	case err == redis.Nil:
		return "", status.Errorf(codes.NotFound, "Token Not Exist %v", err)
	case err != nil:
		return "", status.Errorf(codes.Internal, "Unable To Fetch Value %v", err)
	case val == "":
		return "", status.Errorf(codes.Unknown, "Empty Value %v", err)
	}

	return val, nil
}

func (dataService *DataServices) SetDataToCash(ctx context.Context, key string, value interface{}, expiration time.Duration) error {

	err := dataService.Cash.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to add data to cash  : %w", err)
	}

	fmt.Println("Adding Data For : " + key + " in cash")

	return nil
}

func (dataService *DataServices) DelDataFromCash(ctx context.Context, key string) error {

	err := dataService.Cash.Del(ctx, key).Err()

	if err != nil {
		return status.Errorf(codes.NotFound, "No Data Is Found", err)
	}

	return nil
}

/*

Load the phone and email in cash for fast response
While creating user only insert authenticated user in database
In first request insert the details of user in cash and if he/she conforms the details/otp then only insert the record in database.

*/
