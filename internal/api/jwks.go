package api

import (
	"log"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

type JwksResponse struct {
	Keys []jwk.Key `json:"keys"`
}

func (a *API) Jwks(w http.ResponseWriter, r *http.Request) error {
	config := a.config
	resp := JwksResponse{
		Keys: []jwk.Key{},
	}

	for _, key := range config.JWT.Keys {
		log.Printf("Key: %v", key.PublicKey)
		log.Printf("KeyType: %v", key.PublicKey.KeyType())
		log.Printf("KeyID: %v", key.PublicKey.KeyID())
		log.Printf("KeyType Expected: %v", jwa.OctetSeq)
		// don't expose hmac jwk in endpoint
		if key.PublicKey == nil {
			continue
		}
		resp.Keys = append(resp.Keys, key.PublicKey)
	}

	w.Header().Set("Cache-Control", "public, max-age=600")
	return sendJSON(w, http.StatusOK, resp)
}
