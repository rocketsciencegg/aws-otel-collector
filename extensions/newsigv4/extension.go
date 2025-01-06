// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package newsigv4 // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/sigv4authextension"

import (
	"context"
	"errors"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/fsnotify/fsnotify"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/extension/auth"
	"go.uber.org/zap"
	grpcCredentials "google.golang.org/grpc/credentials"
)

// sigv4Auth is a struct that implements the auth.Client interface.
// It provides the implementation for providing Sigv4 authentication for HTTP requests only.
type sigv4Auth struct {
	cfg        *Config
	logger     *zap.Logger
	awsSDKInfo string
	watcher    *fsnotify.Watcher
}

// compile time check that the sigv4Auth struct satisfies the auth.Client interface
var _ auth.Client = (*sigv4Auth)(nil)

// RoundTripper() returns a custom signingRoundTripper.
func (sa *sigv4Auth) RoundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	cfg := sa.cfg

	signer := sigv4.NewSigner()

	// Create the signingRoundTripper struct
	rt := signingRoundTripper{
		transport:     base,
		signer:        signer,
		region:        cfg.Region,
		service:       cfg.Service,
		credsProvider: cfg.credsProvider,
		awsSDKInfo:    sa.awsSDKInfo,
		logger:        sa.logger,
	}

	return &rt, nil
}

// PerRPCCredentials is implemented to satisfy the auth.Client interface but will not be implemented.
func (sa *sigv4Auth) PerRPCCredentials() (grpcCredentials.PerRPCCredentials, error) {
	return nil, errors.New("not implemented")
}

// Start is implemented to satisfy the component.Component interface. Start
// is called on extension inialization and will setup the fsnotify
// file watcher when credentials are provided by a shared credentials file
// that requires refreshing over time.
func (sa *sigv4Auth) Start(_ context.Context, host component.Host) error {
	if sa.cfg.SharedCredentialsWatcher.FileLocation != "" {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			componentstatus.ReportStatus(host, componentstatus.NewFatalErrorEvent(err))
			return nil
		}
		sa.watcher = watcher

		if err := sa.startWatcher(); err != nil {
			componentstatus.ReportStatus(host, componentstatus.NewFatalErrorEvent(err))
		}
		sa.logger.Info("Started credentials file watcher")
	}

	return nil
}

// Shutdown is implemented to satisfy the component.Component interface. Shutdown
// closes any open fsnotify watches. Any goroutines active from startWatcher will
// subsequently exit safely.
func (sa *sigv4Auth) Shutdown(_ context.Context) error {
	if sa.watcher != nil {
		if err := sa.watcher.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (sa *sigv4Auth) startWatcher() error {
	location := sa.cfg.SharedCredentialsWatcher.FileLocation

	// invalidator is a local copy of the internal interface for cache invalidators
	// from the AWS Go SDK.
	// https://github.com/aws/aws-sdk-go-v2/blob/main/internal/sdk/interfaces.go
	type invalidator interface {
		Invalidate()
	}

	cache, ok := (*sa.cfg.credsProvider).(invalidator)
	if !ok {
		return nil
	}

	go func() {
		for {
			select {
			case event, ok := <-sa.watcher.Events:
				if !ok {
					return
				}

				if event.Has(fsnotify.Create | fsnotify.Write | fsnotify.Rename) {
					sa.logger.Info("Detected changes within shared credentials file")
					cache.Invalidate()
				}
			case err, ok := <-sa.watcher.Errors:
				if !ok {
					return
				}

				sa.logger.Error("Error event from file watcher", zap.Error(err))
			}
		}
	}()

	if err := sa.watcher.Add(location); err != nil {
		return err
	}

	return nil
}

// newSigv4Extension() is called by createExtension() in factory.go and
// returns a new sigv4Auth struct.
func newSigv4Extension(cfg *Config, awsSDKInfo string, logger *zap.Logger) *sigv4Auth {
	return &sigv4Auth{
		cfg:        cfg,
		logger:     logger,
		awsSDKInfo: awsSDKInfo,
	}
}

// getCredsProviderFromConfig() is a helper function that gets AWS credentials
// from the Config.
func getCredsProviderFromConfig(cfg *Config) (*aws.CredentialsProvider, error) {
	awscfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.AssumeRole.STSRegion),
	)
	if err != nil {
		return nil, err
	}

	var provider aws.CredentialsProvider

	// Create new wrapped CredentialProvider from awscfg
	if cfg.SharedCredentialsWatcher.FileLocation != "" {
		provider = &sharedCredentialsProvider{
			sfile:   cfg.SharedCredentialsWatcher.FileLocation,
			profile: cfg.SharedCredentialsWatcher.ProfileName,
		}
	}

	if cfg.AssumeRole.ARN != "" {
		stsSvc := sts.NewFromConfig(awscfg)

		provider = stscreds.NewAssumeRoleProvider(stsSvc, cfg.AssumeRole.ARN)
	}

	if provider != nil {
		awscfg.Credentials = aws.NewCredentialsCache(provider)
	}

	_, err = awscfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, err
	}

	return &awscfg.Credentials, nil
}
