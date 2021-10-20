package api

import (
	"regexp"
	"testing"

	"github.com/hashicorp/eventlogger/filters/encrypt"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertFiltering will assert that the specified filtering has been applied to
// the event.
// Supported options are:
//	WithRedactedRequestAttrs: assert redacted request attributes
//	WithRedactedResponseAttrs: assert redacted request attributes
//
// 	WithRedactedRequestParameters: assert redacted request parameters
// 	WithRedactedResponseParameters: assert redacted request parameters
//
//	WithEncryptedRequestAttrs: assert redacted request attributes
//	WithEncryptedResponseAttrs: assert redacted request attributes
func AssertFiltering(t *testing.T, e *cloudevents.Event, opt ...Option) {
	t.Helper()
	require := require.New(t)
	require.NotNil(e)
	opts := getOpts(opt...)

	AssertRedactedAttrs(t, e, "request", opts.withRedactedRequestAttrs)
	AssertRedactedAttrs(t, e, "response", opts.withRedactedResponseAttrs)

	AssertRedactedParameters(t, e, "request", opts.withRedactedRequestParameters)
	AssertRedactedParameters(t, e, "response", opts.withRedactedResponseParameters)

	AssertEncryptedAttrs(t, e, "request", opts.withEncryptedRequestAttrs)
	AssertEncryptedAttrs(t, e, "response", opts.withEncryptedResponseAttrs)
}

// AssertRedactedParameters will assert that the specified parameters have been
// redacted from the msgType (request/response)
func AssertRedactedParameters(t *testing.T, e *cloudevents.Event, msgType string, parameterNames []string) {
	t.Helper()
	if parameterNames == nil {
		return
	}
	assert, require := assert.New(t), require.New(t)
	require.NotNil(e)
	require.NotNil(parameterNames)
	eventParamaters := getParameters(t, e, msgType)
	rMap := make(map[string]bool, len(parameterNames))
	for _, s := range parameterNames {
		rMap[s] = true
	}
	for k, v := range eventParamaters {
		if _, ok := rMap[k]; ok {
			assert.Equalf(encrypt.RedactedData, v, "expected %s to be redacted and it was set to: %s", k, v)
		} else {
			assert.NotEqualf(encrypt.RedactedData, v, "did not expect %s to be redacted", k)
		}
	}
}

// AssertRedactedAttrs will assert that the specified attributes have been
// redacted from the msgType (request/response)
func AssertRedactedAttrs(t *testing.T, e *cloudevents.Event, msgType string, attributeNames []string) {
	t.Helper()
	if attributeNames == nil {
		return
	}
	assert, require := assert.New(t), require.New(t)
	if attributeNames == nil {
		return
	}
	require.NotNil(e)
	require.NotEmpty(msgType)
	eventAttrs := getAttributes(t, e, msgType)
	rMap := make(map[string]bool, len(attributeNames))
	for _, s := range attributeNames {
		rMap[s] = true
	}
	for k, v := range eventAttrs {
		if _, ok := rMap[k]; ok {
			assert.Equalf(encrypt.RedactedData, v, "expected %s to be redacted and it was set to: %s", k, v)
		} else {
			assert.NotEqualf(encrypt.RedactedData, v, "did not expect %s to be redacted", k)
		}
	}
}

// AssertEncryptedAttrs will assert that the specified attributes have been
// encrypted in the msgType (request/response)
func AssertEncryptedAttrs(t *testing.T, e *cloudevents.Event, msgType string, attributeNames []string) {
	t.Helper()
	if attributeNames == nil {
		return
	}
	assert, require := assert.New(t), require.New(t)
	if attributeNames == nil {
		return
	}
	require.NotNil(e)
	require.NotEmpty(msgType)
	eventAttrs := getAttributes(t, e, msgType)
	rMap := make(map[string]bool, len(attributeNames))
	for _, s := range attributeNames {
		rMap[s] = true
	}
	for k, v := range eventAttrs {
		if _, ok := rMap[k]; ok {
			assert.Regexpf(regexp.MustCompile(`^encrypted:`), v, "expected %s to be encrypted and it was set to: %s", k, v)
		} else {
			assert.NotRegexpf(regexp.MustCompile(`^encrypted:`), v, "did not expect %s to be redacted", k)
		}
	}
}
