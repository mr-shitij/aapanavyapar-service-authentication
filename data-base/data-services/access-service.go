package data_services

const (
	ForgetPassword = 0
	ConformContact = 1
	ResendOTP      = 2
	GetNewToken    = 3
	LogOut         = 4
	NoOne          = 5
	All            = 6
	External       = 7
	NewPassToken   = 8
)

func IsHasAccessTo(accessGroup []int, access int) bool {
	for _, a := range accessGroup {
		if a == access {
			return true
		}
	}
	return false
}
