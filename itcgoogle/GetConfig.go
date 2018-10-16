package itcgoogle

import (
	"errors"
	"log"

	parser "github.com/kkesley/s3-parser"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

//GetConfigInput holds the s3 bucket details of the secret credentials. Also holds the required scope for the application
type GetConfigInput struct {
	Bucket string
	Region string
	Key    string
	Scope  []string
}

//GetConfig get credentials config
func GetConfig(input GetConfigInput) (*oauth2.Config, error) {
	if len(input.Bucket) <= 0 || len(input.Region) <= 0 || len(input.Key) <= 0 {
		return nil, errors.New("Credentials input cannot be null")
	}
	b, err := parser.GetS3DocumentDefault(input.Region, input.Bucket, input.Key)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
		return nil, err
	}
	// If modifying these scopes, delete your previously saved token.json.
	return google.ConfigFromJSON(b, input.Scope...)
}
