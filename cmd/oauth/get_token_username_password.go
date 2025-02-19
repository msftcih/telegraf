package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type Data struct {
    Login string `json:"login"`
}

type Response struct {
    Data Data `json:"data"`
}

func main() {
	method := "POST"
	url := os.Getenv("oauth_url")
	client_id := os.Getenv("client_id")
	client_secret := os.Getenv("client_secret")
	oauth_content_type := os.Getenv("oauth_content_type")
	output_file := "/tmp/telegraf/access_token"
	error_file := "/tmp/telegraf/errors"
	e, err := os.Create(error_file)
	
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
	"query":"mutation { login(username: \"` + client_id + `\", password: \"` + client_secret + `\")}"
	}`)
	
	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		e.WriteString(err.Error())
		fmt.Println(err)
		return
	}
	
	req.Header.Add("Content-Type", oauth_content_type)
	res, err := client.Do(req)
	if err != nil {
			e.WriteString(err.Error())
			log.Fatal(err)
			fmt.Println(err)
		return
	}
	
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
			e.WriteString(err.Error())
			log.Fatal(err)
			fmt.Println(err)
		return
	}

	var authToken Response
	json.Unmarshal([]byte(string(body)), &authToken)
	
	f, err := os.Create(output_file)
	if err != nil {
		log.Fatal(err)
	}
	
	tokenIndex := strings.Index(authToken.Data.Login, "Bearer ")
	if tokenIndex == -1 {
		fmt.Println("Substring not found")
		return
	}
	
	token := authToken.Data.Login[tokenIndex + len("Bearer "):]	
	f.WriteString(token)
}
