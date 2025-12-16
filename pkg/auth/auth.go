package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/nanobot-ai/nanobot/pkg/mcp"
	"github.com/nanobot-ai/nanobot/pkg/types"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/oauth/validate"
	"github.com/obot-platform/mcp-oauth-proxy/pkg/proxy"
	proxytypes "github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

type Auth struct {
	OAuthClientID     string   `usage:"OAuth client ID"`
	OAuthClientSecret string   `usage:"OAuth client secret"`
	OAuthAuthorizeURL string   `usage:"OAuth authorize URL for third-party OAuth provider"`
	OAuthTokenURL     string   `usage:"OAuth token URL for third-party OAuth provider"`
	OAuthScopes       []string `usage:"OAuth scopes to request during OAuth flow"`
	TrustedIssuer     string   `usage:"Trusted issuer for JWT tokens"`
	JWKS              string   `usage:"JWKS public key for JWT tokens"`
	TrustedAudiences  []string `usage:"Trusted audiences for JWT tokens"`
	EncryptionKey     string   `usage:"Encryption key for storing sensitive data"`
}

func Wrap(ctx context.Context, env map[string]string, auth Auth, dsn, address, healthzPath string, runningUI bool, oauthCallbackHandler mcp.CallbackServer, next http.Handler) (http.Handler, error) {
	if auth.OAuthClientID == "" {
		return next, nil
	}

	result, err := setupContext(auth, next)
	if err != nil {
		return nil, err
	}

	if auth.OAuthClientID != "" {
		if auth.OAuthClientSecret == "" {
			return nil, fmt.Errorf("oauthClientSecret is required")
		}
		if auth.OAuthAuthorizeURL == "" {
			return nil, fmt.Errorf("oauthAuthorizeURL is required")
		}

		result, err = mcpProxy(auth, dsn, result)
		if err != nil {
			return nil, fmt.Errorf("failed to create oauth proxy: %w", err)
		}
	}

	return result, nil
}

func userFromHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		var user mcp.User
		keys := map[string]any{}
		_ = mcp.JSONCoerce(user, &keys)
		for key := range keys {
			v := req.Header.Get("X-Forwarded-" + strings.ReplaceAll(key, "_", "_"))
			if key == "email_verified" {
				keys[key] = v == "true"
			} else {
				keys[key] = v
			}
		}
		_ = mcp.JSONCoerce(keys, &user)

		if user.ID == "" {
			user.ID = user.Sub
		}
		if user.ID == "" {
			user.ID = user.Login
		}

		nctx := types.NanobotContext(req.Context())
		nctx.User = user
		next.ServeHTTP(rw, req.WithContext(types.WithNanobotContext(mcp.WithUser(req.Context(), user), nctx)))
	})
}

func setupContext(auth Auth, next http.Handler) (http.Handler, error) {
	if auth.OAuthClientID == "" {
		return userFromHeaders(next), nil
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		info := validate.GetTokenInfo(req)
		if info != nil {
			var user mcp.User
			infoString, ok := info.Props["info"].(string)
			if ok {
				_ = json.Unmarshal([]byte(infoString), &user)
			}
			nctx := types.NanobotContext(req.Context())
			nctx.User = user
			nctx.User.ID = info.UserID
			req = req.WithContext(types.WithNanobotContext(req.Context(), nctx))
		}
		next.ServeHTTP(rw, req)
	}), nil
}

func mcpProxy(auth Auth, dsn string, next http.Handler) (_ http.Handler, err error) {
	hash := sha256.Sum256([]byte(strings.TrimSpace(auth.EncryptionKey)))

	if !strings.Contains(dsn, "postgres") {
		dsn = strings.TrimSuffix(dsn, ".db") + "_auth.db"
	}

	proxy, err := proxy.NewOAuthProxy(&proxytypes.Config{
		DatabaseDSN:       dsn,
		OAuthClientID:     auth.OAuthClientID,
		OAuthClientSecret: auth.OAuthClientSecret,
		OAuthAuthorizeURL: auth.OAuthAuthorizeURL,
		ScopesSupported:   strings.Join(auth.OAuthScopes, ","),
		EncryptionKey:     base64.StdEncoding.EncodeToString(hash[:]),
		Mode:              "middleware",
		//CookieName:        "nanobot_auth_code",
		//RequiredAuthPaths: []string{"/mcp", "/api"},
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	proxy.SetupRoutes(mux, next)
	return mux, nil
}
