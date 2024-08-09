package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evecloud/auth/internal/conf"
	"github.com/evecloud/auth/internal/crypto"
	"github.com/evecloud/auth/internal/models"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type InviteTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration

	token string
}

func TestInvite(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &InviteTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *InviteTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Setup response recorder with super admin privileges
	ts.token = ts.makeSuperAdmin("")
}

func (ts *InviteTestSuite) makeSuperAdmin(email string) string {
	// Cleanup existing user, if they already exist
	if u, _ := models.FindUserByEmail(ts.API.db, email); u != nil {
		require.NoError(ts.T(), ts.API.db.Destroy(u), "Error deleting user")
	}

	u, err := models.NewUser("123456789", email, "test", ts.Config.JWT.Aud, map[string]interface{}{"full_name": "Test User"})
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u))

	var token string

	session, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	req := httptest.NewRequest(http.MethodPost, "/invite", nil)
	token, err = ts.API.generateAccessToken(req, ts.API.db, u, &session.ID, models.Invite)

	require.NoError(ts.T(), err, "Error generating access token")

	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	require.NoError(ts.T(), err, "Error parsing token")

	return token
}

func (ts *InviteTestSuite) TestInvite() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *InviteTestSuite) TestInviteAfterSignupShouldNotReturnSensitiveFields() {
	// To allow us to send signup and invite request in succession
	ts.Config.SMTP.MaxFrequency = 5
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    "test@example.com",
		"password": "test123",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req = httptest.NewRequest(http.MethodPost, "/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	x := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(x, req)

	require.Equal(ts.T(), http.StatusOK, x.Code)

	data := models.User{}
	require.NoError(ts.T(), json.NewDecoder(x.Body).Decode(&data))
	// Sensitive fields
	require.Equal(ts.T(), 0, len(data.Identities))
	require.Equal(ts.T(), 0, len(data.UserMetaData))
}

func (ts *InviteTestSuite) TestInvite_WithoutAccess() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusUnauthorized, w.Code) // 401 OK because the invite request above has no Authorization header
}

func (ts *InviteTestSuite) TestVerifyInvite() {
	cases := []struct {
		desc        string
		email       string
		requestBody map[string]interface{}
		expected    int
	}{
		{
			"Verify invite with password",
			"test@example.com",
			map[string]interface{}{
				"email":    "test@example.com",
				"type":     "invite",
				"token":    "asdf",
				"password": "testing",
			},
			http.StatusOK,
		},
		{
			"Verify invite with no password",
			"test1@example.com",
			map[string]interface{}{
				"email": "test1@example.com",
				"type":  "invite",
				"token": "asdf",
			},
			http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			user, err := models.NewUser("", c.email, "", ts.Config.JWT.Aud, nil)
			now := time.Now()
			user.InvitedAt = &now
			user.ConfirmationSentAt = &now
			user.EncryptedPassword = nil
			user.ConfirmationToken = crypto.GenerateTokenHash(c.email, c.requestBody["token"].(string))
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Create(user))
			require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, user.ID, user.GetEmail(), user.ConfirmationToken, models.ConfirmationToken))

			// Find test user
			_, err = models.FindUserByEmail(ts.API.db, c.email)
			require.NoError(ts.T(), err)

			// Request body
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.requestBody))

			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
			req.Header.Set("Content-Type", "application/json")

			// Setup response recorder
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			assert.Equal(ts.T(), c.expected, w.Code, w.Body.String())
		})
	}
}
