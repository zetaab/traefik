package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

func TestNewOidcError(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})

	auth := dynamic.OidcAuth{}

	_, err := NewOidc(context.Background(), next, auth, "authName")
	assert.Error(t, err)
}

var noRedirectClient = http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func TestNewOidc(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := []string{}
		for name, values := range r.Header {
			// Loop over all values for the name.
			if name == "X-User-Groups" || name == "X-User-Email" {
				for _, value := range values {
					content = append(content, fmt.Sprintf("%s=%s", name, value))
				}
			}
		}
		sort.Strings(content)
		for _, c := range content {
			fmt.Fprintln(w, c)
		}
	})

	m, err := mockoidc.NewServer(nil)
	m.AccessTTL = 2 * time.Second
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	err = m.Start(ln, nil)
	require.NoError(t, err)

	defer func() {
		err := m.Shutdown()
		if err != nil {
			t.Fatal(err)
		}
	}()
	cfg := m.Config()
	auth := dynamic.OidcAuth{
		Issuer:       m.Issuer(),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		ForwardHeaders: map[string]string{
			"X-User-Email":  "email",
			"X-User-Groups": "groups",
		},
		ACL: dynamic.ACL{
			Allow: []string{"group:engineering", "group:design"},
			Deny:  []string{"group:marketing"},
		},
	}

	_, err = NewOidc(context.Background(), next, auth, "authName")
	assert.ErrorContains(t, err, "acl deny and allow cannot be both set")

	auth.ACL = dynamic.ACL{}
	handler, err := NewOidc(context.Background(), next, auth, "authName")
	require.NoError(t, err)

	type testCase struct {
		name       string
		statusCode int
		path       string
		preFunc    func()
		postFunc   func(*httptest.ResponseRecorder)
		body       string
		cookies    []*http.Cookie
	}

	stateValue := "stateCookie"
	testCases := []testCase{
		{
			name:       "unauthenticated request should redirect",
			statusCode: 303,
			path:       "/",
		},
		{
			name:       "success callback state cookie not found",
			statusCode: 500,
			body:       "state cookie not found\n",
			path:       callback,
		},
		{
			name:       "success callback state did not match",
			statusCode: 500,
			body:       "state did not match\n",
			path:       callback,
			cookies: []*http.Cookie{
				{
					Name:  state,
					Value: stateValue,
				},
			},
		},
		{
			name:       "success callback code missing",
			statusCode: 500,
			body:       "code or state missing\n",
			path:       fmt.Sprintf("%s?state=%s", callback, stateValue),
			cookies: []*http.Cookie{
				{
					Name:  state,
					Value: stateValue,
				},
			},
		},
		{
			name:       "success callback, invalid code",
			statusCode: 500,
			body:       "unable to exchange token oauth2: \"invalid_grant\" \"Invalid code: 6666\"\n",
			path:       fmt.Sprintf("%s?state=%s&code=6666", callback, stateValue),
			cookies: []*http.Cookie{
				{
					Name:  state,
					Value: stateValue,
				},
			},
		},
		{
			name:       "success callback",
			statusCode: 303,
			path:       fmt.Sprintf("%s?state=%s&code=12345", callback, stateValue),
			cookies: []*http.Cookie{
				{
					Name:  state,
					Value: stateValue,
				},
				{
					Name:  nextURI,
					Value: "/nexturi",
				},
			},
			preFunc: func() {
				m.QueueCode("12345")
				u, err := url.Parse(m.AuthorizationEndpoint())
				require.NoError(t, err)
				q := u.Query()
				q.Set("access_type", "online")
				q.Set("client_id", cfg.ClientID)
				q.Set("redirect_uri", "http://localhost/_callback")
				q.Set("response_type", "code")
				q.Set("scope", "openid profile email groups")
				q.Set("state", stateValue)
				u.RawQuery = q.Encode()
				finalURL := u.String()
				res, err := noRedirectClient.Get(finalURL)
				require.NoError(t, err)
				require.Equal(t, 302, res.StatusCode)
				loc, err := res.Location()
				require.NoError(t, err)
				require.Equal(t, fmt.Sprintf("http://localhost/_callback?code=12345&state=%s", stateValue), loc.String())
			},
			postFunc: func(w *httptest.ResponseRecorder) {
				loc, err := w.Result().Location()
				require.NoError(t, err)
				require.Equal(t, "https://example.com/nexturi", loc.String())
				var cookie *http.Cookie
				for _, c := range w.Result().Cookies() {
					if c.Name == session {
						cookie = c
					}
				}
				require.NotNil(t, cookie)
				w2 := httptest.NewRecorder()
				req2 := httptest.NewRequest(http.MethodGet, "/", nil)
				req2.AddCookie(cookie)
				handler.ServeHTTP(w2, req2)
				body := w2.Body.String()
				require.Equal(t, 200, w2.Code, body)
				resp := `X-User-Email=jane.doe@example.com
X-User-Groups=engineering,design
`
				require.Equal(t, resp, body)

				// test expiry token
				time.Sleep(5 * time.Second)
				w3 := httptest.NewRecorder()
				req3 := httptest.NewRequest(http.MethodGet, "/", nil)
				req3.AddCookie(cookie)
				handler.ServeHTTP(w3, req3)
				require.Equal(t, 303, w3.Code, w3.Body.String())
				loc, err = w3.Result().Location()
				require.NoError(t, err)
				require.Contains(t, loc.String(), "authorize")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.preFunc != nil {
				tc.preFunc()
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}
			handler.ServeHTTP(w, req)
			body := w.Body.String()
			require.Equal(t, tc.statusCode, w.Code, body)
			if tc.postFunc != nil {
				tc.postFunc(w)
			}
			if len(tc.body) > 0 {
				require.Equal(t, tc.body, body)
			}
		})
	}
}

func TestOIDCWhiteList(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "traefik")
	})

	m, err := mockoidc.NewServer(nil)
	m.AccessTTL = 2 * time.Second
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	err = m.Start(ln, nil)
	require.NoError(t, err)

	defer func() {
		err := m.Shutdown()
		if err != nil {
			t.Fatal(err)
		}
	}()

	cfg := m.Config()
	auth := dynamic.OidcAuth{
		Issuer:       m.Issuer(),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		WhitelistIPs: []string{"1.1.1.1"},
	}

	handler, err := NewOidc(context.Background(), next, auth, "authName")
	require.NoError(t, err)

	type testCase struct {
		name       string
		statusCode int
		RemoteAddr string
		body       string
	}

	testCases := []testCase{
		{
			name:       "not allowed ip",
			statusCode: 303,
		},
		{
			name:       "allowed ip",
			statusCode: 200,
			body:       "traefik\n",
			RemoteAddr: "1.1.1.1",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.RemoteAddr != "" {
				req.RemoteAddr = tc.RemoteAddr
			}
			handler.ServeHTTP(w, req)
			body := w.Body.String()
			require.Equal(t, tc.statusCode, w.Code, body)
			if len(tc.body) > 0 {
				require.Equal(t, tc.body, body)
			}
		})
	}
}

func TestOIDCACL(t *testing.T) {
	type testCase struct {
		name string
		acl  dynamic.ACL
		grps []string
		err  error
	}

	testCases := []testCase{
		{
			name: "allow, no acl rules in place",
			err:  nil,
		},
		{
			name: "allow user because it has grp1",
			acl: dynamic.ACL{
				Allow: []string{"group:grp1"},
			},
			grps: []string{"foo", "group:grp1", "bar"},
		},
		{
			name: "deny user because it has no grp1",
			acl: dynamic.ACL{
				Allow: []string{"group:grp1"},
			},
			grps: []string{"foo", "group:grp2", "bar"},
			err:  fmt.Errorf("access denied"),
		},
		{
			name: "deny user because it has grp1",
			acl: dynamic.ACL{
				Deny: []string{"group:grp1"},
			},
			grps: []string{"foo", "group:grp1", "bar"},
			err:  fmt.Errorf("access denied"),
		},
		{
			name: "allow user because it has grp1",
			acl: dynamic.ACL{
				Deny: []string{"group:grp1"},
			},
			grps: []string{"foo", "group:grp2", "bar"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkACL(tc.acl, tc.grps)
			require.Equal(t, tc.err, err)
		})
	}
}
