package authmethods_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"

	tests_api "github.com/hashicorp/boundary/internal/tests/api"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticate tests the api calls and the audit events it should produce
func TestAuthenticate(t *testing.T) {
	// this cannot run in parallel because it relies on envvar
	// globals.BOUNDARY_DEVELOPER_ENABLE_EVENTS
	event.TestEnableEventing(t, true)

	assert, require := assert.New(t), require.New(t)
	eventConfig := event.TestEventerConfig(t, "TestAuthenticateAuditEntry", event.TestWithAuditSink(t))
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	require.NoError(event.InitSysEventer(testLogger, testLock, "TestAuthenticateAuditEntry", event.WithEventerConfig(&eventConfig.EventerConfig)))
	tcConfig, err := config.DevController()
	require.NoError(err)
	tcConfig.Eventing = &eventConfig.EventerConfig

	tc := controller.NewTestController(t, &controller.TestControllerOpts{Config: tcConfig})
	defer tc.Shutdown()

	client := tc.Client()
	methods := authmethods.NewClient(client)

	tok, err := methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.NotNil(tok)

	_, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "wrong"})
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValuesf(http.StatusUnauthorized, apiErr.Response().StatusCode(), "Expected unauthorized, got %q", apiErr.Message)

	// Also ensure that, for now, using "credentials" still works, as well as no command.
	reqBody := map[string]interface{}{
		"attributes": map[string]interface{}{"login_name": "user", "password": "passpass"},
	}
	req, err := client.NewRequest(tc.Context(), "POST", fmt.Sprintf("auth-methods/%s:authenticate", tc.Server().DevPasswordAuthMethodId), reqBody)
	require.NoError(err)
	resp, err := client.Do(req)
	require.NoError(err)

	result := new(authmethods.AuthenticateResult)
	apiErr, err = resp.Decode(result)
	require.NoError(err)
	require.Nil(apiErr)

	token := new(authtokens.AuthToken)
	require.NoError(json.Unmarshal(result.GetRawAttributes(), token))
	require.NotEmpty(token.Token)

	//
	// This section will test that the audit events for the api requests are
	// properly redacted.
	//

	require.NotNil(eventConfig.AuditEvents)
	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls

	tok, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "passpass"})
	require.NoError(err)
	assert.NotNil(tok)
	b, err := ioutil.ReadFile(eventConfig.AuditEvents.Name())
	assert.NoError(err)

	got := &cloudevents.Event{}
	err = json.Unmarshal(b, got)
	require.NoErrorf(err, "json: %s", string(b))

	tests_api.AssertFiltering(t, got,
		tests_api.WithRedactedRequestAttrs(t, []string{"password"}),
		tests_api.WithRedactedResponseAttrs(t, []string{"token"}),
		tests_api.WithRedactedRequestParameters(t, []string{}),
		tests_api.WithRedactedResponseParameters(t, []string{}),
	)

	_ = os.WriteFile(eventConfig.AuditEvents.Name(), nil, 0o666) // clean out audit events from previous calls
	tok, err = methods.Authenticate(tc.Context(), tc.Server().DevPasswordAuthMethodId, "login", map[string]interface{}{"login_name": "user", "password": "bad-pass"})
	require.Error(err)
	assert.Nil(tok)
	b, err = ioutil.ReadFile(eventConfig.AuditEvents.Name())
	assert.NoError(err)

	got = &cloudevents.Event{}
	err = json.Unmarshal(b, got)
	require.NoErrorf(err, "json: %s", string(b))

	tests_api.AssertFiltering(t, got,
		tests_api.WithRedactedRequestAttrs(t, []string{"password"}),
		tests_api.WithRedactedRequestParameters(t, []string{}),
	)
}
