package main
//script to issue oauth2 token requests from telegraf
//Usage: get_oauth2_token_password_credentials.go <oauth_url> <oauth_issue_type-new/refresh> <access_token_file> <refresh_token_file>
//refresh_token_file is optional and only required for refresh token requests
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
	oauth_url := os.Args[1]
	oauth_issue_type := os.Args[2]
	client_id := os.Getenv("client_id")
	client_secret := os.Getenv("client_secret")
	username := os.Getenv("username")
	password := os.Getenv("password")
	oauth_content_type := os.Getenv("oauth_content_type")
	var output_file string
	var refresh_token_file string
	var oauth_grant_type string
	
	if len(os.Args) > 3 {
		output_file = os.Args[3]
	} else {
		output_file = "/tmp/telegraf/access_token"
	}
    if len(os.Args) > 4 {
        refresh_token_file = os.Args[4]
    } else {
		refresh_token_file = "/tmp/telegraf/refresh_token"
	}
	
	
	if oauth_issue_type == "new" {
		oauth_grant_type = os.Getenv("oauth_grant_type")
	} else if oauth_issue_type == "refresh" {
		oauth_grant_type = "refresh_token"
	} else {
		log.Println("invalid oauth_issue_type")
		return
	}

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

	req_body := url.Values{}
	req_body.Set("username", username)
	req_body.Set("password", password)
	req_body.Set("grant_type", oauth_grant_type)
	// Add refresh token header if oauth_issue_type is refresh
    if oauth_issue_type == "refresh" {
        refreshToken, err := ioutil.ReadFile(refresh_token_file)
        if err != nil {
            log.Fatal(err)
        }
        req_body.Set("refresh_token", string(refreshToken))
    }

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

	// Write refresh token to file if it exists in response
    if authToken.RefreshToken != "" {
        rf, err := os.Create(refresh_token_file)
        if err != nil {
            log.Fatal(err)
        }
        defer rf.Close()
        rf.WriteString(authToken.RefreshToken)
    }
}
