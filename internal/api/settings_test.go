package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSettings_DefaultProviders(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/settings", nil)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, w.Code, http.StatusOK)
	resp := Settings{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	p := resp.Providers

	require.True(t, p.Apple)
	require.True(t, p.Microsoft)
	require.True(t, p.Google)
	require.True(t, p.GitHub)

}

func TestSettings_EmailDisabled(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	config.External.Email.Enabled = false

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/settings", nil)
	req.Header.Set("Content-Type", "application/json")

	ctx := context.Background()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, w.Code, http.StatusOK)
	resp := Settings{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
}
