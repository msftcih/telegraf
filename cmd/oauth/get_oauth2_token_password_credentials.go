package main
//script to issue oauth2 token requests from telegraf
//Usage: get_oauth2_token_password_credentials.go -u <oauth_url> -i <oauth_issue_type-new/refresh> -o <access_token_file> -r <refresh_token_file> -ca <ca_cert_file> -cert <client_cert_file> -key <client_key_file> -data <json_data> -token-key <token_key_name> -refresh-token-key <refresh_token_key_name>
//refresh_token_file is optional and only required for refresh token requests
//cert and key are optional and used for mTLS authentication
//data is optional JSON string that will be sent as request body (overrides default form-encoded body)
//token-key is optional, defaults to "access_token" - specifies the JSON key path for the access token in response (supports nested keys like "data.token")
//refresh-token-key is optional, defaults to "refresh_token" - specifies the JSON key path for the refresh token in response (supports nested keys)
//error-file is optional, defaults to "/tmp/telegraf/token_generation_error" - where errors will be written
//Environment variables (client_id, client_secret, username, password, oauth_grant_type, oauth_content_type) are all optional
import (
	"crypto/tls"
    "crypto/x509"
    "encoding/json"
	"flag"
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

// getNestedValue extracts a value from nested JSON using dot notation (e.g., "data.token")
func getNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	keys := strings.Split(path, ".")
	var current interface{} = data
	
	for _, key := range keys {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[key]; exists {
				current = val
			} else {
				return nil, false
			}
		} else {
			return nil, false
		}
	}
	
	return current, true
}

func main() {
	method := "POST"
	oauth_url := flag.String("u", "", "OAuth URL")
	oauth_issue_type := flag.String("i", "new", "OAuth Issue Type")
	client_id := os.Getenv("client_id")
	client_secret := os.Getenv("client_secret")
	username := os.Getenv("username")
	password := os.Getenv("password")
	oauth_grant_type := os.Getenv("oauth_grant_type")
	oauth_content_type := os.Getenv("oauth_content_type")
	output_file := flag.String("o", "/tmp/telegraf/access_token", "Access Token File")
	refresh_token_file := flag.String("r", "/tmp/telegraf/refresh_token", "Refresh Token File")
	caCertFile := flag.String("ca", "", "CA Cert File")
	clientCertFile := flag.String("cert", "", "Client Cert File for mTLS")
	clientKeyFile := flag.String("key", "", "Client Key File for mTLS")
	jsonData := flag.String("data", "", "JSON data to send as request body")
	tokenKey := flag.String("token-key", "access_token", "JSON key path for access token in response (supports nested keys like 'data.token')")
	refreshTokenKey := flag.String("refresh-token-key", "refresh_token", "JSON key path for refresh token in response (supports nested keys)")
	errorFile := flag.String("error-file", "/tmp/telegraf/token_generation_error", "Error log file")

	flag.Parse()
	
	// Helper function to write errors to both log and file
	writeError := func(errMsg string) {
		log.Println(errMsg)
		if ef, err := os.Create(*errorFile); err == nil {
			ef.WriteString(errMsg + "\n")
			ef.Close()
		}
	}
	
	if *oauth_url == "" {
		writeError("OAuth URL is required")
        log.Fatal("OAuth URL is required")
    }

	var payload *strings.Reader
	
	// If custom JSON data is provided, use it as the request body
	if *jsonData != "" {
		payload = strings.NewReader(*jsonData)
	} else {
		// Default form-encoded body
		req_body := url.Values{}
		req_body.Set("username", username)
		req_body.Set("password", password)
		// Add refresh token header if oauth_issue_type is refresh
		if *oauth_issue_type == "refresh" {
			refreshToken, err := ioutil.ReadFile(*refresh_token_file)
			oauth_grant_type = "refresh_token"
			if err != nil {
				log.Fatal(err)
			}
			req_body.Set("refresh_token", string(refreshToken))
		}
		req_body.Set("grant_type", oauth_grant_type)
		payload = strings.NewReader(req_body.Encode())
	}
	
	// Configure TLS client
	tlsConfig := &tls.Config{}
	
	// Load CA cert if provided
	if *caCertFile != "" {
		caCert, err := ioutil.ReadFile(*caCertFile)
		if err != nil {
			errMsg := fmt.Sprintf("Error reading CA cert file: %v", err)
			writeError(errMsg)
			log.Fatalf(errMsg)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	
	// Load client cert and key for mTLS if provided
	if *clientCertFile != "" && *clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile)
		if err != nil {
			errMsg := fmt.Sprintf("Error loading client cert/key: %v", err)
			writeError(errMsg)
			log.Fatalf(errMsg)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		log.Println("mTLS enabled with client certificate")
	} else if *clientCertFile != "" || *clientKeyFile != "" {
		errMsg := "Both -cert and -key must be provided for mTLS"
		writeError(errMsg)
		log.Fatal(errMsg)
	}
	
	// Create HTTP client with TLS configuration if any TLS settings were configured
	client := &http.Client{}
	if *caCertFile != "" || (*clientCertFile != "" && *clientKeyFile != "") {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}
	req, err := http.NewRequest(method, *oauth_url, payload)

	if err != nil {
		errMsg := fmt.Sprintf("Error creating HTTP request: %v", err)
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}
	
	// Only add Basic Auth if client_id and client_secret are provided
	if len(client_id) > 0 && len(client_secret) > 0 {
		auth := base64.StdEncoding.EncodeToString([]byte(client_id + ":" + client_secret))
		req.Header.Set("Authorization", "Basic " + auth)
	}
	
	// Set Content-Type if provided
	if len(oauth_content_type) > 0 {
		req.Header.Add("Content-Type", oauth_content_type)
	}
    
	res, err := client.Do(req)
	if err != nil {
		errMsg := fmt.Sprintf("Error executing HTTP request: %v", err)
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}
	
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Error reading response body: %v", err)
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}

	// Check HTTP status code
	if res.StatusCode >= 400 {
		errMsg := fmt.Sprintf("HTTP request failed with status %d: %s\nResponse body: %s", res.StatusCode, res.Status, string(body))
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}

	// Parse response as generic JSON map to support configurable token keys
	var responseData map[string]interface{}
	if err := json.Unmarshal(body, &responseData); err != nil {
		errMsg := fmt.Sprintf("Error parsing JSON response: %v\nResponse body: %s", err, string(body))
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}

	// Extract access token using the configured key path (supports nested keys)
	var accessToken string
	if tokenValue, ok := getNestedValue(responseData, *tokenKey); ok {
		if tokenStr, ok := tokenValue.(string); ok {
			accessToken = tokenStr
		} else {
			errMsg := fmt.Sprintf("Token value for key path '%s' is not a string. Response: %s", *tokenKey, string(body))
			writeError(errMsg)
			log.Fatal(errMsg)
			return
		}
	} else {
		errMsg := fmt.Sprintf("Token key path '%s' not found in response. Response: %s", *tokenKey, string(body))
		writeError(errMsg)
		log.Fatal(errMsg)
		return
	}

	// Write access token to file
	f, err := os.Create(*output_file)
	if err != nil {
		errMsg := fmt.Sprintf("Error creating access token file: %v", err)
		writeError(errMsg)
		log.Fatal(errMsg)
	}
	defer f.Close()
	f.WriteString(accessToken)

	// Write refresh token to file if it exists in response (supports nested keys)
	if refreshTokenValue, ok := getNestedValue(responseData, *refreshTokenKey); ok {
		if refreshTokenStr, ok := refreshTokenValue.(string); ok && refreshTokenStr != "" {
			rf, err := os.Create(*refresh_token_file)
			if err != nil {
				errMsg := fmt.Sprintf("Error creating refresh token file: %v", err)
				writeError(errMsg)
				log.Fatal(errMsg)
			}
			defer rf.Close()
			rf.WriteString(refreshTokenStr)
		}
	}
	
	// Clear error file on success
	os.Remove(*errorFile)
}
