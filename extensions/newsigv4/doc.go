// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate mdatagen metadata.yaml

// Package newsigv4 implements the `auth.Client` interface.
// This extension provides the Sigv4 process of adding authentication information to AWS API requests sent by HTTP.
// As such, the extension can be used for HTTP based exporters that export to AWS services.
package newsigv4 // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/sigv4authextension"
