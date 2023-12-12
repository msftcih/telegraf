package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	client_id := os.Getenv("client_id")
	client_secret := os.Getenv("client_secret")
	subscriptionKey := os.Getenv("subscriptionkey")
	oauth_audience := os.Getenv("oauth_audience")
	oauth_scope := os.Getenv("oauth_scope")
	oauth_grant_type := os.Getenv("oauth_grant_type")
	oauth_content_type := os.Getenv("oauth_content_type")
	output_file := "/tmp/telegraf/access_token"	
	
	if len(client_id) == 0 {
		log.Printf("invalid client_id, %d\n", len(client_id))
		return
	}

	if len(client_secret) == 0 {
		log.Println("invalid client_secret")
		return
	}

	if len(output_file) == 0 {
		log.Println("invalid output file")
		return
	}

	var payload = strings.NewReader(`{
	"client_id":"` + client_id + `",
	"client_secret":"` + client_secret + `",
	"audience":"` + oauth_audience + `",
	"grant_type":"` + oauth_grant_type + `"
	}`)

	if len(oauth_content_type) > 0 && strings.EqualFold(oauth_content_type, "application/x-www-form-urlencoded") {
		body := url.Values{}
		body.Set("client_id", client_id)
		body.Set("client_secret", client_secret)
		body.Set("grant_type", oauth_grant_type)
		
		if len(oauth_scope) > 0 {
			body.Set("scope", oauth_scope)
		}
		
		if len(oauth_audience) > 0 {
			body.Set("audiance", oauth_audience)
		}

		payload = strings.NewReader(body.Encode())
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, baseUrl, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	
	if len(subscriptionKey) > 0 {
		req.Header.Add("Ocp-Apim-Subscription-Key", subscriptionKey)
	}
	
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
	fmt.Println(string(body))

	var authToken AuthToken
	json.Unmarshal([]byte(string(body)), &authToken)

	f, err := os.Create(output_file)
	if err != nil {
		log.Fatal(err)
	}
	f.WriteString(authToken.AccessToken)
}
