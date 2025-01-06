package newsigv4

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSharedCredentialsProvider_Retrieve(t *testing.T) {
	t.Run("Retrieve valid credentials from a temp file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "shared-credentials")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		sampleProfile := `[default]
aws_access_key_id = TEST_ACCESS_KEY
aws_secret_access_key = TEST_SECRET_KEY
`
		_, err = tmpFile.WriteString(sampleProfile)
		require.NoError(t, err)

		// Close the file so the provider can read it properly.
		err = tmpFile.Close()
		require.NoError(t, err)

		provider := &sharedCredentialsProvider{
			profile: "default",
			sfile:   tmpFile.Name(),
		}
		creds, err := provider.Retrieve(context.Background())
		require.NoError(t, err)

		require.Equal(t, creds.AccessKeyID, "TEST_ACCESS_KEY")
		require.Equal(t, creds.SecretAccessKey, "TEST_SECRET_KEY")
	})
}
