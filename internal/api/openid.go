package api

import (
	"net/http"
)

type OpenIDConfigurationResponse struct {
	Issuer                            string   `json:"issuer"`
	Authorization                     string   `json:"authorization_endpoint"`
	Token                             string   `json:"token_endpoint"`
	UserInfo                          string   `json:"userinfo_endpoint"`
	JWKS                              string   `json:"jwks_uri"`
	Scopes                            []string `json:"scopes_supported"`
	ResponseTypes                     []string `json:"response_types_supported"`
	CodeChallengeMethods              []string `json:"code_challenge_methods_supported"`
	ResponseModes                     []string `json:"response_modes_supported"`
	SubjectTypes                      []string `json:"subject_types_supported"`
	Claims                            []string `json:"claims_supported"`
	TokenEndpointAuthSigningAlgValues []string `json:"token_endpoint_auth_signing_alg_values_supported"`
}

func (a *API) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) error {
	config := a.config
	resp := OpenIDConfigurationResponse{
		Issuer:                            config.JWT.Issuer,
		Authorization:                     config.API.URL + "/authorize",
		Token:                             config.API.URL + "/token",
		UserInfo:                          config.API.URL + "/userinfo",
		JWKS:                              config.API.URL + "/.well-known/jwks.json",
		Scopes:                            []string{"openid"},
		ResponseTypes:                     []string{"code", "token"},
		CodeChallengeMethods:              []string{"plain", "S256"},
		ResponseModes:                     []string{"query"},
		SubjectTypes:                      []string{"public"},
		Claims:                            []string{"iss", "sub", "aud", "exp", "iat", "sid"},
		TokenEndpointAuthSigningAlgValues: []string{"RS256"},
	}

	return sendJSON(w, http.StatusOK, resp)
}
