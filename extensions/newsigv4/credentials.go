package newsigv4

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

type sharedCredentialsProvider struct {
	sfile   string
	profile string
}

// Retrieve returns fresh credentials from the given shared
// credentials file.
func (s *sharedCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	sharedcfg, err := config.LoadSharedConfigProfile(ctx, s.profile, func(opts *config.LoadSharedConfigOptions) {
		opts.CredentialsFiles = []string{s.sfile}
	})
	if err != nil {
		return aws.Credentials{}, err
	}

	return sharedcfg.Credentials, nil
}
