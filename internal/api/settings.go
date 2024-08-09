package api

import "net/http"

type ProviderSettings struct {
	Apple     bool `json:"apple"`
	Microsoft bool `json:"microsoft"`
	GitHub    bool `json:"github"`
	Google    bool `json:"google"`
}

type Settings struct {
	Providers ProviderSettings `json:"providers"`
	Email     bool             `json:"email"`
	SAML      bool             `json:"saml"`
}

func (a *API) Settings(w http.ResponseWriter, r *http.Request) error {
	config := a.config

	return sendJSON(w, http.StatusOK, &Settings{
		Providers: ProviderSettings{
			Apple:     config.External.Apple.Enabled,
			Microsoft: config.External.Microsoft.Enabled,
			GitHub:    config.External.Github.Enabled,
			Google:    config.External.Google.Enabled,
		},
		Email: config.External.Email.Enabled,
		SAML:  config.SAML.Enabled,
	})
}
