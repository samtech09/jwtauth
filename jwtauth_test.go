package jwtauth

import (
	"testing"
)

func TestVerifyToken(t *testing.T) {

	vc := ValidatorConfig{}

	vc.JWTAudience = "https://ts02.mrsdigitech.com:8050"
	vc.JWTIssuer = "mah-auth-srv-t01"
	vc.JWTTimeSkew = 5

	v := InitValidator(vc, "public.pem")

	// Hint: get token from Postman, by calling Token api
	token := "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6Ly90czAyLm1yc2RpZ2l0ZWNoLmNvbTo4MDUwIl0sImV4cCI6MTU3ODY4NjI2MCwiaWF0IjoxNTc4NjUwMjYwLCJpc3MiOiJtYWgtYXV0aC1zcnYtdDAxIiwiYXBwIjoiUG9zdG1hbiIsImNpZCI6ImQ4Y2M4MjMyLTE2ZTEtNGVjNy05YjQ5LTg4MzMyMjkzODI1ZiIsInNjb3BlIjoidmlld2VyLHB1Ymxpc2hlcix1c2VyIn0.CZ3v5nqDmh4gxadK3WCLQT_HlGmkrCOimRuKth3QTnipah6uklj5o0G4S0Dun9uStknxjDtSayap4lmeyoX0x31duOWPUQNS5LGAJ9Rn-NBksKxtIz4RuRYPP2wWkVpQ-0QLr0PunqgeP6EFIpJPp4rkJhz_f4n_wCTV-kvtpZ0tbv9o5B1dkYKGpF-9a5CUbbbc-splepHH_bUBMnsjrV46v9yHZ3toq3RmgAfbFgzpiN-fffACa1ISmbGY1acCcjSYyZfZ_rQ-q9FA6XdqUdbzdE_eh6fXKKe06aYg1nRJpWtGrwTxSyv7UOespUn5kQfSZdOMw8KSB0IXc-5orA"

	ci, err := v.ValidateToken(token, "127.0.0.1")
	if err != nil {
		t.Error(err)
	}

	if ci.AppName != "Postman" {
		t.Error("Expect app: Postman,  Got: ", ci.AppName)
	}

}
