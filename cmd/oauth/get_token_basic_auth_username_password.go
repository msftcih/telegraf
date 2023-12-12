package main

import (
	"encoding/json"
	"encoding/base64"
	"mime/multipart"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type AuthToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int32  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	method := "POST"
	baseUrl := os.Getenv("oauth_url")
	clientID := os.Getenv("client_id")
	clientSecret := os.Getenv("client_secret")
	username := os.Getenv("basicauth_username")
	password := os.Getenv("basicauth_password")
	grantType := os.Getenv("oauth_grant_type")
	contentType := os.Getenv("oauth_content_type")
	output_file := "/tmp/telegraf/access_token"	
	
	var payload bytes.Buffer
    w := multipart.NewWriter(&payload)

    if err := w.WriteField("username", clientID); err != nil {
        return
    }
    if err := w.WriteField("password", clientSecret); err != nil {
        return
    }
    if err := w.WriteField("grant_type", grantType); err != nil {
        return
    }
	
	w.Close()
	
	req, err := http.NewRequest(method, baseUrl, &payload)
    if err != nil {
        return
    }

	if(strings.EqualFold(contentType, "form-data")) {
		req.Header.Set("Content-Type", w.FormDataContentType())
	}
	
	if(!strings.EqualFold(contentType, "form-data")) {
		req.Header.Add("Content-Type", contentType)
	}	

    // Basic Auth
    auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
    req.Header.Set("Authorization", "Basic "+auth)

    // Do the request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
			log.Fatal(err)
			fmt.Println(err)
		return
	}
	fmt.Println(string(body))

	var authToken AuthToken
	json.Unmarshal([]byte(string(body)), &authToken)

	f, err := os.Create(output_file)
	if err != nil {
		log.Fatal(err)
	}
	f.WriteString(authToken.AccessToken)
}
