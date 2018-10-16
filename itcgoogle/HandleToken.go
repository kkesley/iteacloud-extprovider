package itcgoogle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"

	"golang.org/x/oauth2"
	gauth "google.golang.org/api/oauth2/v2"
)

//DateFormat to parse date from google
const DateFormat = "2006-01-02 15:04:05.999999999 -0700 MST"

//HandleTokenInput holds the input for the request
type HandleTokenInput struct {
	ITCService    string
	UserARN       string
	RequireSecret bool
	Config        *oauth2.Config
}

//HandleTokenOutput holds the response
type HandleTokenOutput struct {
	RequireAuth bool
	AuthURL     *string
	Profile     *Profile
}

//Profile holds authenticated profile
type Profile struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	PictureURL string `json:"picture_url"`
}

// Request a token from the web, then returns the auth url
func getAuthURL(config *oauth2.Config) string {
	return config.AuthCodeURL("some-state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

func getCachedToken(svc *dynamodb.DynamoDB, input HandleTokenInput, config *oauth2.Config) (*oauth2.Token, error) {
	// get token from dynamodb
	var queryInput = &dynamodb.GetItemInput{
		TableName:       aws.String(os.Getenv("DATA_TABLE")),
		AttributesToGet: []*string{aws.String("refresh_token"), aws.String("access_token"), aws.String("expiry_time"), aws.String("token_type")},
		Key: map[string]*dynamodb.AttributeValue{
			"userARN": {
				S: aws.String(input.UserARN),
			},
			"type": {
				S: aws.String(input.ITCService + "_GOOGLE_CREDS"),
			},
		},
	}

	resp, err := svc.GetItem(queryInput)
	if err != nil {
		return nil, err
	}
	token := new(oauth2.Token)
	if refreshToken, ok := resp.Item["refresh_token"]; ok && refreshToken.S != nil {
		token.RefreshToken = *refreshToken.S
	}
	if accessToken, ok := resp.Item["access_token"]; ok && accessToken.S != nil {
		token.AccessToken = *accessToken.S
	}
	if expiryTime, ok := resp.Item["expiry_time"]; ok && expiryTime.S != nil {
		if exp, err := time.Parse(DateFormat, strings.Split(*expiryTime.S, " m=")[0]); err == nil {
			token.Expiry = exp
		}
	}
	if tokenType, ok := resp.Item["token_type"]; ok && tokenType.S != nil {
		token.TokenType = *tokenType.S
	}
	newToken, err := config.TokenSource(context.TODO(), token).Token()
	if err != nil {
		return nil, err
	}
	if !newToken.Valid() {
		return nil, errors.New("Invalid Token")
	}
	return newToken, nil
}

func refreshToken(config *oauth2.Config, token *oauth2.Token) (*http.Client, error) {
	return config.Client(context.Background(), token), nil
}

// Retrieve a token, saves the token, then returns the generated client.
func getOutput(svc *dynamodb.DynamoDB, input HandleTokenInput, config *oauth2.Config) (*HandleTokenOutput, error) {
	output := HandleTokenOutput{}
	token, err := getCachedToken(svc, input, config)
	if err != nil {
		output.RequireAuth = true
		output.AuthURL = aws.String(getAuthURL(config))
		return &output, nil
	}
	gsrv, err := gauth.New(config.Client(context.Background(), token))
	if err != nil {
		return nil, err
	}
	me, err := gsrv.Userinfo.V2.Me.Get().Do()
	if err != nil {
		return nil, err
	}
	output.Profile = &Profile{
		Email:      me.Email,
		Name:       me.Name,
		PictureURL: me.Picture,
	}
	updateInput := &dynamodb.UpdateItemInput{
		TableName: aws.String(os.Getenv("DATA_TABLE")),
		Key: map[string]*dynamodb.AttributeValue{
			"userARN": {S: aws.String(input.UserARN)},
			"type":    {S: aws.String(input.ITCService + "_GOOGLE_CREDS")},
		},
		ExpressionAttributeNames: map[string]*string{
			":refresh_token": aws.String("refresh_token"),
			":access_token":  aws.String("access_token"),
			":expiry_time":   aws.String("expiry_time"),
			":token_type":    aws.String("token_type"),
			":email":         aws.String("email"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			"#refresh_token": &dynamodb.AttributeValue{S: aws.String(token.RefreshToken)},
			"#access_token":  &dynamodb.AttributeValue{S: aws.String(token.AccessToken)},
			"#expiry_time":   &dynamodb.AttributeValue{S: aws.String(token.Expiry.Format(time.RFC3339))},
			"#token_type":    &dynamodb.AttributeValue{S: aws.String(token.TokenType)},
			"#email":         &dynamodb.AttributeValue{S: aws.String(me.Email)},
		},
		UpdateExpression: aws.String("SET :refresh_token = #refresh_token, :access_token = #access_token, :expiry_time = #expiry_time, :token_type = #token_type, :email = #email"),
		ReturnValues:     aws.String("UPDATED_NEW"),
	}

	svc.UpdateItem(updateInput)
	return &output, nil
}

//HandleToken returns current user profile or required auth url
func HandleToken(input HandleTokenInput) (*HandleTokenOutput, error) {
	if input.Config == nil && input.RequireSecret {
		return nil, errors.New("Credentials input cannot be null")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("DATA_TABLE_REGION"))},
	)

	if err != nil {
		fmt.Println("Got error creating session:")
		return nil, err
	}

	svc := dynamodb.New(sess)
	getOutput(svc, input, input.Config)
	return nil, nil
}
