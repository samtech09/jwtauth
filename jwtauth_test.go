package jwtauth

import (
	"testing"
)

func TestVerifyToken(t *testing.T) {

	vc := ValidatorConfig{}

	vc.JWTAudience = "https://ps02.digitech.com:8050"
	vc.JWTIssuer = "mah-auth-srv-t01"
	vc.JWTTimeSkew = 5

	v := InitValidator(vc, "public.pem")

	// Hint: get token from Postman, by calling Token api
	token := "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6Ly90czAyLm1yc2RpZ2l0ZWNoLmNvbTo4MDUwIl0sImV4cCI6MTU3OTEwOTc3OCwiaWF0IjoxNTc5MDczNzc4LCJpc3MiOiJtYWgtYXV0aC1zcnYtdDAxIiwiYXBwIjoiUG9zdG1hbiIsImNpZCI6ImQ4Y2M4MjMyLTE2ZTEtNGVjNy05YjQ5LTg4MzMyMjkzODI1ZiIsInNjb3BlIjoidmlld2VyLHB1Ymxpc2hlcix1c2VyIn0.wKgAZTzqJpozKbLOjWAB-UHQYFe9qSBVYfdvGT71tWCooK9bLNu08mS4uGFxr5Yr3x2KpwdujnemSIc8vO3XfM5GCKuzxjWyQY42PWUbXR3PXe64N2pQEW8cZMMPbmW-C3zA01QS4wUr-qhju1d_8FYbxImP3Xulobs1XtV4ctS_l2UXTMmb9tUF0wGzhJFJlX_vv-IXv__Ue4wmbzJ4iii09r69b82AWBn6J8Cz19-zgc-DnOEpDsUtHnXpU10hfTE41Z0V1LQfmY3oujWVAmx4MUK1p9ACWPyCBxWLu8uTJCnY1eb13YWux_eXa19uvZwENREvoWeAFHqYx2ZB5A"

	ci, err := v.ValidateToken(token, "127.0.0.1")
	if err != nil {
		t.Error(err)
	}

	if ci.AppName != "Postman" {
		t.Error("Expect app: Postman,  Got: ", ci.AppName)
	}

}
