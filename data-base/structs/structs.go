package structs

import (
	"encoding/json"
	"fmt"
	"time"
)

type UserData struct {
	UserId   string `json:"user_id" db:"user_id"`
	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`
	PhoneNo  string `json:"phone_no" db:"phone_no"`
	Email    string `json:"email" db:"email"`
}

type RefreshTokenCashData struct {
	RefreshToken   string `json:"refresh_token"`
	AllocatedToken int32  `json:"allocated_token"`
}

type OTPCashData struct {
	OTP         string    `json:"otp"`
	PhoneNo     string    `json:"phone_no"`
	ResendTimes int32     `json:"resend_times"`
	Time        time.Time `json:"time"`
}

type UserContactDetails struct {
	PhoneNo string `json:"phone_no" db:"phone_no"`
	UserId  string `json:"user_id" db:"user_id"`
}

func (m *RefreshTokenCashData) Marshal() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return data
}

func (m *UserData) Marshal() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return data
}

func (m *OTPCashData) Marshal() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return data
}

func (m *UserContactDetails) Marshal() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return data
}

func UnmarshalTokenCash(data []byte, m *RefreshTokenCashData) {
	err := json.Unmarshal(data, &m)
	if err != nil {
		fmt.Println(err)
	}
}

func UnmarshalOTPCash(data []byte, m *OTPCashData) {
	err := json.Unmarshal(data, &m)
	if err != nil {
		fmt.Println(err)
	}
}

func UnmarshalUserDataCash(data []byte, m *UserData) {
	err := json.Unmarshal(data, &m)
	if err != nil {
		fmt.Println(err)
	}
}
