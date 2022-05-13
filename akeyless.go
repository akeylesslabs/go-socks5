package socks5

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	Status   string      `json:"status"`
	Command  string      `json:"command"`
	Response interface{} `json:"response"`
	Token    string      `json:"token"`
}

func ValidateToken(token string) (bool, error) {
	debug := os.Getenv("DEBUG")
	str := fmt.Sprintf("{\"cmd\":\"validate-token\", \"token\":\"%v\", \"debug\":\"true\"}", token)
	if debug == "true" {
		log.Printf("GW URL:[%s], CMD:[%s]\n", os.Getenv("AKEYLESS_GW_URL"), str)
	}
	resp, err := sendReq(os.Getenv("AKEYLESS_GW_URL"), str)
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
	if curlRes.Status != "success" {
		if debug == "true" {
			log.Printf("Err: status [%s]\n", curlRes.Status)
		}
		return false, nil
	}
	if strings.Contains(resp, `"is_valid": false,`) {
		if debug == "true" {
			log.Printf("Err: invalid [%s]\n", resp)
		}
		return false, nil
	}
	lines, _ := curlRes.Response.([]interface{})
	for _, line := range lines {
		l := fmt.Sprintf("%v", line)
		if strings.HasPrefix(l, "UAM: ") {
			claims, err := ParseUnvalidatedClaimsFromJWT(strings.TrimPrefix(l, "UAM: "))
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
		} else {
			if debug == "true" {
				log.Printf("Err: no uam [%s]\n", l)
			}
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

func sendReq(url, bodyStr string) (string, error) {

	var body io.Reader
	if bodyStr != "" {
		body = bytes.NewReader([]byte(bodyStr))
	}

	req, err := http.NewRequest("POST", url, body)
	req.Header.Set("Content-Type", "application/json")

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

