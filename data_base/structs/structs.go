package structs

import (
	"encoding/json"
	"fmt"
	"time"
)

type UserData struct {
	externalUserId string `db:"external_user_id"`
	internalUserId string `db:"internal_user_id"`
	username       string `db:"username"`
	password       string `db:"password"`
	phoneNo        string `db:"phone_no"`
	email          string `db:"email"`
	pinCode        string `db:"pin_code"`
}

type RefreshTokenCashData struct {
	RefreshToken string `json:"refresh_token"`
	AllocatedToken int32 `json:"allocated_token"`
}

type OTPCashData struct {
	OTP string `json:"otp"`
	PhoneNo string `json:"phone_no"`
	ResendTimes int32 `json:"resend_times"`
	Time time.Time `json:"time"`
}

func (m *RefreshTokenCashData) Marshal() []byte {
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

func (m *OTPCashData) Marshal() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
	}
	return data
}

func UnmarshalOTPCash(data []byte, m *OTPCashData) {
	err := json.Unmarshal(data, &m)
	if err != nil {
		fmt.Println(err)
	}
}
