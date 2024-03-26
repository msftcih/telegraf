package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"encoding/base64"
	"os"
	"strings"
)

type AuthToken struct {
	AccessToken 	string `json:"access_token"`
	RefreshToken 	string `json:"refresh_token"`
	Scope       	string `json:"scope"`
	ExpiresIn   	int32  `json:"expires_in"`
	TokenType   	string `json:"token_type"`
}

func main() {
	method := "POST"
	oauth_url := os.Getenv("oauth_url")
	client_id := os.Getenv("client_id")
	client_secret := os.Getenv("client_secret")
	username := os.Getenv("username")
	password := os.Getenv("password")
	oauth_grant_type := os.Getenv("oauth_grant_type")
	oauth_content_type := os.Getenv("oauth_content_type")
	output_file := "/tmp/telegraf/access_token"	
	
	if len(client_id) == 0 {
		log.Printf("invalid client_id with length , %d\n", len(client_id))
		return
	}

	if len(client_secret) == 0 {
		log.Println("invalid client_secret")
		return
	}

	if len(username) == 0 {
		log.Printf("invalid username, %d\n", len(username))
		return
	}

	if len(password) == 0 {
		log.Println("invalid password")
		return
	}

	if len(output_file) == 0 {
		log.Println("invalid output file")
		return
	}

	req_body := url.Values{}
	req_body.Set("username", username)
	req_body.Set("password", password)
	req_body.Set("grant_type", oauth_grant_type)

	var payload = strings.NewReader(req_body.Encode())
	
	client := &http.Client{}
	req, err := http.NewRequest(method, oauth_url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	
	auth := base64.StdEncoding.EncodeToString([]byte(client_id + ":" + client_secret))
	req.Header.Set("Authorization", "Basic " + auth)
	req.Header.Add("Content-Type", oauth_content_type)

	res, err := client.Do(req)
	if err != nil {
			log.Fatal(err)
			fmt.Println(err)
		return
	}
	
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
			log.Fatal(err)
			fmt.Println(err)
		return
	}

	var authToken AuthToken
	json.Unmarshal([]byte(string(body)), &authToken)

	f, err := os.Create(output_file)
	if err != nil {
		log.Fatal(err)
	}
	f.WriteString(authToken.AccessToken)
}
