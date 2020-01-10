package jwt

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"strings"
)

// Token ...
type Token struct {
	AccessToken map[string]interface{}
}

// JWTHeader ...
type JWTHeader struct {
	ALG string `json:"alg"` // Signing Algorithm
	TYP string `json:"typ"` // Type of 'Token'
	KID string `json:"kid"` // *unique to Centene
}

// JWTPayload ...
type JWTPayload struct {
	ClientID string `json:"client_id"` // *unique to L&R
	ISS      string `json:"iss"`       // issuer
	SUB      string `json:"sub"`       // subject
	AUD      string `json:"aud"`       // audience
	EXP      int    `json:"exp"`       // expiration in NumericDate value
	NBF      string `json:"nbf"`       // defines
	IAT      string `json:"iat"`       // time when issued
	JTI      string `json:"jti"`       // unique id, help prevent 'replay', 'one-time-token'
}

// JWTSignature ...
type JWTSignature struct {
	Secret string
}

// JWT ... JSON Web Token
type JWT struct {
	Header  JWTHeader
	Payload JWTPayload
	Secret  JWTSignature
	Token   Token
}

// RetrieveToken ...
func (j JWT) RetrieveToken(b io.ReadCloser, jwt *JWT) error {
	// convert body to []byte
	body, _ := ioutil.ReadAll(b)
	// convert body json object to struct
	jErr := json.Unmarshal(body, &jwt.Token.AccessToken)
	if jErr != nil {
		return jErr
	}
	return nil
}

// ParseToken ...
func (j JWT) ParseToken(jwt *JWT) error {
	// header.payload.signature
	jwtSegments := strings.Split(jwt.Token.AccessToken["access_token"].(string), ".")
	if len(jwtSegments) <= 1 {
		return errors.New("ERROR_ParseToken_failed___jwtSegments_less_than_or_equal_to_1")
	}
	decodedHeader := decodeSegment(jwtSegments[0])
	// log.Printf("decodedHeader: %v\n", decodedHeader)
	errHeader := json.Unmarshal(decodedHeader, &jwt.Header)
	if errHeader != nil {
		return errors.New("ERROR: ParseToken() Failed to Unmarshal Header: " + errHeader.Error())
	}
	decodePayload := decodeSegment(jwtSegments[1])
	// log.Printf("decodePayload: %v\n", decodePayload)
	errPayload := json.Unmarshal(decodePayload, &jwt.Payload)
	if errPayload != nil {
		return errors.New("ERROR: ParseToken() Failed to Unmarshal Payload: " + errPayload.Error())
	}
	// Sign(jwt.Header.ALG, jwtSegments[0] + "." + jwtSegments[1], jwtSegments[2])
	return nil
}

// Sign ... (jwt.Header.ALG, jwtSegments[0] + "." + jwtSegments[1], jwtSegments[2])
func Sign(algorithm string, headerPlusPayload string, signature string) {
	//
}

func decodeSegment(str string) []byte {
	decoded, _ := b64.StdEncoding.DecodeString(str)
	if strings.Count(string(decoded), "}") == 0 {
		t1 := string(decoded)
		t1 += "}"
		return []byte(t1)
	}
	return decoded
}
