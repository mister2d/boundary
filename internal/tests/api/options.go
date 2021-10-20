package api

import (
	"testing"

	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/stretchr/testify/require"
)

func WithRedactedRequestAttrs(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withRedactedRequestAttrs = names
	}
}

func WithRedactedResponseAttrs(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withRedactedResponseAttrs = names
	}
}

func WithEncryptedRequestAttrs(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withEncryptedRequestAttrs = names
	}
}

func WithEncryptedResponseAttrs(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withEncryptedResponseAttrs = names
	}
}

func WithRedactedRequestParameters(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withRedactedRequestParameters = names
	}
}

func WithRedactedResponseParameters(t *testing.T, names []string) Option {
	t.Helper()
	return func(o *options) {
		o.withRedactedResponseParameters = names
	}
}

func getAttributes(t *testing.T, e *cloudevents.Event, messageType string) map[string]interface{} {
	t.Helper()
	require := require.New(t)
	require.NotNil(e)
	require.NotEmpty(messageType)
	data, ok := e.Data.(map[string]interface{})
	if !ok {
		return nil
	}
	msgType, ok := data[messageType].(map[string]interface{})
	if !ok {
		return nil
	}

	details, ok := msgType["details"].(map[string]interface{})
	if !ok {
		return nil
	}
	attrs, ok := details["attributes"].(map[string]interface{})
	if !ok {
		return nil
	}
	return attrs
}

func getParameters(t *testing.T, e *cloudevents.Event, messageType string) map[string]interface{} {
	t.Helper()
	require := require.New(t)
	require.NotNil(e)
	require.NotEmpty(messageType)
	data, ok := e.Data.(map[string]interface{})
	if !ok {
		return nil
	}
	msgType, ok := data[messageType].(map[string]interface{})
	if !ok {
		return nil
	}

	details, ok := msgType["details"].(map[string]interface{})
	if !ok {
		return nil
	}
	return details
}

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withRedactedRequestAttrs  []string // test only option
	withRedactedResponseAttrs []string // test only option

	withRedactedRequestParameters  []string // test only option
	withRedactedResponseParameters []string // test only option

	withEncryptedRequestAttrs  []string // test only option
	withEncryptedResponseAttrs []string // test only option
}

func getDefaultOptions() options {
	return options{}
}
