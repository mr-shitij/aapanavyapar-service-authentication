# Authentication service for aapanavypar

This service is created to enable authentication mechanism in aapanavypar application.

## Services

- **[Signup](#Signup) ( To Create Account ).**

- **[ContactConformation](#ContactConformation) ( To Conform Contact ).**

- **[ResendOTP](#ResendOTP) ( To Resend OTP ).**

- **[GetNewToken](#GetNewToken) ( To Get New Auth Token ).**

- **[SignInWithMail](#SignInWithMail) ( To Login Into Your Account ).**

- **[Logout](#Logout) ( To Logout From Account ).**

- **[ForgetPassword](#ForgetPassword) ( To Initiate Forget Password Flow ).**

- **[ConformForgetPasswordOTP](#ConformForgetPasswordOTP) ( To Validate Your Identity To Forget Password Service ).**

- **[SetNewPassword](#SetNewPassword) ( To Set New Password ).**

### Signup

Request

    message SignUpRequest {
        string username = 25;
        string password = 26;
        string phoneNo = 27;
        string email = 28;
        string pinCode = 29;

    }  
    
Response 
  
    message SignUpResponse {
        oneof data {
            ResponseData responseData = 40;
            ProblemCode code = 32;
        }
        bool authorized = 50;
    }


### ContactConformation

Request

    message ContactConformationRequest {
        string token = 33;
        string otp = 34;
    }


Response

    message ContactConformationResponse {
        string token = 35;
        string refreshToken = 36;
    }


### ResendOTP

Request

    message ResendOTPRequest {
        string token = 54;
    }

Response

    message ResendOTPResponse {
        OTPResponse response = 55;
        google.protobuf.Duration timeToWaitForNextRequest = 56;
    }

### GetNewToken

Request

    message newTokenRequest {
        string refreshToken = 21;
    }

Response

    message newTokenResponse {
        string token = 22;
    }

### SignInWithMail

Request

    message SignInForMailBaseRequest {
        string mail = 8;
        string password = 9;
    }

Response

    message SignInForMailBaseResponse {
        oneof data{
            ResponseData responseData = 10;
            ProblemCode code = 11;
        }
    }

### Logout

Request

    message LogoutRequest {
        string token = 36;
    }

Response

    message LogoutResponse{
        bool status = 37;
    }

### ForgetPassword

Request

    message ForgetPasswordRequest {
        string phoNo = 55;
    }

Response

    message ForgetPasswordResponse {
        oneof data{
            ResponseData responseData = 10;
            ProblemCode code = 11;
        }
    }

### ConformForgetPasswordOTP

Request

    message ConformForgetPasswordOTPRequest {
        string otp = 59;
        string token = 60;
    }

Response

    message ConformForgetPasswordOTPResponse {
        string newPassToken = 71;
    }

### SetNewPassword

Request

    message SetNewPasswordRequest {
        string newPassToken = 72;
        string newPassword = 73;
    }

Response

    message SetNewPasswordResponse {
        bool status = 74;
    }
