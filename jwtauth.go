package jwtauth

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"crypto/rsa"
	"crypto/x509"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

var pubKey *rsa.PublicKey
var pubKeyLoaded bool

//ValidatorConfig holds config to initialize JWT validator
type ValidatorConfig struct {
	JWTIssuer   string
	JWTAudience string
	//JWTTimeSkew specifies the duration in minutes in which iat, exp and nbf claims may differ by
	JWTTimeSkew int
}

//Validator holds config for JWT token validation along with public key
type Validator struct {
	config *ValidatorConfig
	pubKey *rsa.PublicKey
}

//ClientInfo holds client info extracted from JWT token
type ClientInfo struct {
	ID        string   `json:",omitempty"`
	AppName   string   `json:",omitempty"`
	IPAddr    string   `json:",omitempty"`
	Scopes    []string `json:",omitempty"`
	ScopesCSV string   `json:",omitempty"`
}

//InitValidator initialize JWT validator config and load public key
func InitValidator(config ValidatorConfig, publicKeyFilepath string) *Validator {
	// try to load publickey
	v := Validator{}
	v.config = &config
	pkey, err := loadRSAPublicKey(publicKeyFilepath)
	if err != nil {
		panic("public key load error")
	}
	v.pubKey = pkey
	return &v
}

//ValidateRequest extract token from request and validate
func (v *Validator) ValidateRequest(r *http.Request) (*ClientInfo, error) {
	// try to extract token fromAuth header
	token, err := extractToken(r)
	if err != nil {
		return nil, err
	}
	//g.Logger.Debugm("ValidateToken", "Token: %s", token)

	// check if token is empty
	if token == "" {
		//g.Logger.Debugm("failed to get token", "")
		return nil, fmt.Errorf("failed to get token")
	}

	return v.ValidateToken(token, r.RemoteAddr)
}

//ValidateToken validates given JWT token and return Claimset
func (v *Validator) ValidateToken(token string, remoteAddr string) (*ClientInfo, error) {
	// Get token object from token-string
	tk, err := jwt.ParseString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %s", err)
	}

	// verify standard claims (iat, exp, nbf) with TimeSkew
	// also verify issuer and audience
	//  along with signature
	err = tk.Verify(
		jwt.WithVerify(jwa.RS256, v.pubKey),
		jwt.WithAcceptableSkew(time.Duration(v.config.JWTTimeSkew)*time.Minute),
		jwt.WithIssuer(v.config.JWTIssuer),
		jwt.WithAudience(v.config.JWTAudience))
	if err != nil {
		//g.Logger.Debugm("invalid token: %s", err.Error())
		return nil, fmt.Errorf("token verification failed: %s", err)
	}

	//Extract claims and populate ClientInfo
	ci := ClientInfo{}
	if val, ok := tk.Get("cid"); ok {
		ci.ID = val.(string)
	}
	if val, ok := tk.Get("app"); ok {
		ci.AppName = val.(string)
	}
	if val, ok := tk.Get("scope"); ok {
		ci.ScopesCSV = val.(string)
		ci.Scopes = strings.Split(ci.ScopesCSV, ",")
	}
	ci.IPAddr = remoteAddr

	return &ci, nil
}

func loadRSAPublicKey(pubkeyfile string) (*rsa.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(pubkeyfile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)

	pubkeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubky, ok := pubkeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot get public key")
	}
	pubKey = pubky
	pubKeyLoaded = true
	return pubKey, nil
}

//ExtractToken extracts JWT token from From Autorization hHeader
func extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}
