package itcgoogle

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// ExchangeToken uses id_token to exchange with auth token returns the retrieved token.
func ExchangeToken(config *oauth2.Config) (*oauth2.Token, error) {
	authURL := config.AuthCodeURL("some-state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)
	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		fmt.Println(err)
		return nil, err
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return tok, nil
}
