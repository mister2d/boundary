package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	t.Run("WithRedactedRequestAttrs", func(t *testing.T) {
		opts := getOpts(WithRedactedRequestAttrs(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withRedactedRequestAttrs = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRedactedResponseAttrs", func(t *testing.T) {
		opts := getOpts(WithRedactedResponseAttrs(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withRedactedResponseAttrs = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRedactedRequestParameters", func(t *testing.T) {
		opts := getOpts(WithRedactedRequestParameters(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withRedactedRequestParameters = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithRedactedResponseParameters", func(t *testing.T) {
		opts := getOpts(WithRedactedResponseParameters(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withRedactedResponseParameters = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEncryptedRequestAttrs", func(t *testing.T) {
		opts := getOpts(WithEncryptedRequestAttrs(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withEncryptedRequestAttrs = []string{"test"}
		assert.Equal(opts, testOpts)
	})
	t.Run("WithEncryptedResponseAttrs", func(t *testing.T) {
		opts := getOpts(WithEncryptedResponseAttrs(t, []string{"test"}))
		testOpts := getDefaultOptions()
		testOpts.withEncryptedResponseAttrs = []string{"test"}
		assert.Equal(opts, testOpts)
	})
}
