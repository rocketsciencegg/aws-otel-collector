// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package aws // import "github.com/amazon-contributing/opentelemetry-collector-contrib/override/aws"

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/request"
	"go.uber.org/zap"
)

const (
	DefaultIMDSRetries = 1
)

type IMDSRetryer struct {
	client.DefaultRetryer
	logger *zap.Logger
}

// NewIMDSRetryer allows us to retry imds errors
func NewIMDSRetryer(retryNumber int) IMDSRetryer {
	imdsRetryer := IMDSRetryer{
		DefaultRetryer: client.DefaultRetryer{
			NumMaxRetries: retryNumber,
		},
	}
	logger, err := zap.NewDevelopment()
	if err == nil {
		imdsRetryer.logger = logger
	}
	return imdsRetryer
}

func (r IMDSRetryer) ShouldRetry(req *request.Request) bool {
	// there is no enum of error codes
	// EC2MetadataError is not retryable by default
	// Fallback to SDK's built in retry rules
	shouldRetry := false
	var awsError awserr.Error
	if r.DefaultRetryer.ShouldRetry(req) || (errors.As(req.Error, &awsError) && awsError != nil && awsError.Code() == "EC2MetadataError") {
		shouldRetry = true
	}
	if r.logger != nil {
		r.logger.Debug("imds error : ", zap.Bool("shouldRetry", shouldRetry), zap.Error(req.Error))
	}
	return shouldRetry
}
