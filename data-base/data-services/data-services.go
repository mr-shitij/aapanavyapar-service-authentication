package data_services

import (
	"aapanavyapar_service_authentication/data-base/config"
	"aapanavyapar_service_authentication/data-base/helpers"
	"aapanavyapar_service_authentication/data-base/structs"
	"aapanavyapar_service_authentication/pb"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"strconv"
	"sync"
	"time"
)

type DataServices struct {
	mutex sync.RWMutex
	Db    *sqlx.DB
	Cash  *redis.Client
}

func (dataService *DataServices) CreateUser(ctx context.Context, user *structs.UserData) error {

	res, err := dataService.isUserAlreadyExist(user.Email, user.PhoneNo)
	if err != nil || res {
		return err
	}

	dataService.mutex.Lock()
	defer dataService.mutex.Unlock()

	tx := dataService.Db.MustBegin()

	if err := helpers.ContextError(ctx); err != nil {
		return err
	}

	fmt.Println("Executing Query Now")
	rows := tx.MustExec("insert into user_data (user_id, username, password, phone_no, email, joined_time) values ($1, $2, $3, $4, $5, $6)", user.UserId, user.Username, user.Password, user.PhoneNo, user.Email, time.Now().UTC())

	affected, err := rows.RowsAffected()
	if err != nil {
		return status.Errorf(codes.Internal, "Unable To Get Affected Rows", err)
	}

	if affected <= 0 {
		fmt.Println("User Not Exist")
		return status.Errorf(codes.Unknown, "No Rows Get Affected")
	}

	err = tx.Commit()
	if err != nil {
		return status.Errorf(codes.Internal, "Unable To Commit", err)
	}

	fmt.Print("Created")

	err = dataService.SetContactListDataToCash(ctx, user.PhoneNo, user.UserId)
	if err != nil {
		return err
	}

	return nil
}

func (dataService *DataServices) isUserAlreadyExist(email string, phNo string) (bool, error) {

	dataService.mutex.Lock()
	defer dataService.mutex.Unlock()

	var rows *sqlx.Rows
	var err error

	if email == "" {
		fmt.Println("Email is Empty .. !")

		rows, err = dataService.Db.NamedQuery("select user_id from user_data where phone_no=:phNo", map[string]interface{}{"phNo": phNo})
		if err != nil {
			return true, err
		}

	} else if phNo == "" {
		fmt.Println("Phone No is Empty")
		rows, err = dataService.Db.NamedQuery("select user_id from user_data where email=:email", map[string]interface{}{"email": email})
		if err != nil {
			return true, err
		}

	} else {
		fmt.Println("Both are on place")
		rows, err = dataService.Db.NamedQuery("select user_id from user_data where email=:email or phone_no=:phNo", map[string]interface{}{"email": email, "phNo": phNo})
		if err != nil {
			return true, err
		}

	}
	fmt.Println("Performing Checks : ", email)
	if !rows.Next() {
		fmt.Println("User Not Exist")
		return false, nil //User Not Exist
	}
	return true, status.Errorf(codes.Code(pb.ProblemCode_UserAlreadyExist), "User With Provided Email or Phone Number Already Exist") // User Already Exist
}

func (dataService *DataServices) SignIn(phoneNo string, password string) (string, string, error) {

	dataService.mutex.Lock()
	defer dataService.mutex.Unlock()

	type auth struct {
		Id       string `db:"user_id"`
		Username string `db:"username"`
		Password string `db:"password"`
	}

	var data = auth{}
	err := dataService.Db.Get(&data, "select user_id, username, password from user_data where phone_no=$1", phoneNo)
	if err != nil {
		fmt.Println(err)
		return "", "", status.Errorf(codes.Code(pb.ProblemCode_InvalidUserCredentials), "Invalid Credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(password))
	if err != nil {
		return "", "", status.Errorf(codes.Code(pb.ProblemCode_InvalidPassword), "Invalid Password")
	}

	return data.Id, data.Username, nil

}

func (dataService *DataServices) GetPhoneDetails() (*sqlx.Rows, error) {

	dataService.mutex.RLock()
	defer dataService.mutex.RUnlock()

	rows, err := dataService.Db.Queryx("select phone_no, user_id from user_data")
	if err != nil {
		fmt.Println(err)
		return nil, status.Errorf(codes.Internal, "Unable To Get Data", err)
	}

	return rows, err
}

func NewDbConnection() *DataServices {
	db, err := sqlx.Connect(config.GetDBType(), config.GetPostgresConnectionString())
	if err != nil {
		panic(err)
	}
	dbName, _ := strconv.Atoi(os.Getenv("RedisDB"))

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("RedisAddress"),
		Password: os.Getenv("RedisPassword"), // no password set
		DB:       dbName,                     // use default DB
	})

	return &DataServices{
		Db:   db,
		Cash: rdb,
	}
}

func (dataService *DataServices) UpdatePassword(userId string, newPassword string) error {
	dataService.mutex.Lock()
	defer dataService.mutex.Unlock()

	tx := dataService.Db.MustBegin()

	cost, _ := strconv.Atoi(os.Getenv("cost"))
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), cost)
	if err != nil {
		return status.Errorf(codes.Internal, "Unable To Hash ", err)
	}

	rows := tx.MustExec("update user_data set password=$1 where user_id=$2", hashedPassword, userId)

	err = tx.Commit()

	if err != nil {
		return status.Errorf(codes.Internal, "Unable Complete Update ", err)
	}

	fmt.Println("Performing Checks")
	affected, err := rows.RowsAffected()

	if err != nil {
		return status.Errorf(codes.Internal, "Unable To Get Data ", err)
	}

	if affected <= 0 {
		fmt.Println("User Not Exist")
		return status.Errorf(codes.NotFound, "User Does Not Exists")
	}
	return nil
}
