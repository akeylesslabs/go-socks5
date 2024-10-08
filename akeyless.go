package socks5

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"log"
	"strings"
	"time"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
}

var allowedAccessIds []string

func init() {
	allowedAccessIds = strings.Split(os.Getenv("ALLOWED_ACCESS_IDS"), ",")
}

type CurlOutput struct {
	AuthCreds string   `json:"auth_creds"`
	UamCreds  string   `json:"uam_creds"`
	KfmCreds  string   `json:"kfm_creds"`
	Token     string   `json:"token"`
}

func ValidateToken(token string) (bool, error) {
	debug := os.Getenv("DEBUG")
	if debug == "true" {
		log.Printf("GW URL:[%s], AUTH URL:[%s]\n", os.Getenv("AKEYLESS_GW_URL"), os.Getenv("AKEYLESS_AUTH_URL"))
	}
	resp, err := sendReq(os.Getenv("AKEYLESS_AUTH_URL")+"/get-tmp-creds", token)
	if resp == "" {
		if debug == "true" {
			log.Printf("Err:[%s]\n", "empty response")
		}
		return false, err
	}
	curlRes := CurlOutput{}
	err = json.Unmarshal([]byte(resp), &curlRes)
	if err != nil {
		if debug == "true" {
			log.Printf("Err: json unmarshal [%s]\n", err.Error())
		}
		return false, err
	}
	claims, err := ParseUnvalidatedClaimsFromJWT(curlRes.UamCreds)
	if err != nil {
		if debug == "true" {
			log.Printf("Err: ParseUnvalidatedClaimsFromJWT [%s]\n", err.Error())
		}
		return false, err
	}
	if claims.AccessId == "" {
		if debug == "true" {
			log.Printf("Err: empty [%s]\n", "claims.AccessId")
		}
		return false, err
	}
	for _, id := range allowedAccessIds {
		if id == claims.AccessId {
			log.Printf("Valid AccessId:[%s]\n", claims.AccessId)
			return true, nil
		}
	}

	return false, nil
}

func authWithAkeyless(token string) error {
	if !strings.HasPrefix(token, "t-") && !strings.HasPrefix(token, "u-") {
		return fmt.Errorf("Invalid token")
	}
	if ok, err := ValidateToken(token); !ok || err != nil {
		return fmt.Errorf("Invalid token Error: %v", err)
	}
	return nil
}

func sendReq(url, headerStr string) (string, error) {

	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("akeylessaccesstoken", headerStr)

	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	resbody, err := ioutil.ReadAll(resp.Body)
	return string(resbody), err
}

type Claims struct {
	AccessId      string `json:"access_id"`
	SigningKeyId  string `json:"signing_key_id"`
	Nonce         string `json:"nonce"`
	Type          string `json:"typ"`
	SubjectParams string `json:"sub_params"`
	Attaches      string `json:"attaches"`
}

func ParseUnvalidatedClaimsFromJWT(creds string) (*Claims, error) {
	parts := strings.Split(creds, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token contains an invalid number of segments")
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode segment. %v", err.Error())
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))

	var claims Claims
	if err = dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT. %v", err.Error())
	}
	return &claims, nil
}

