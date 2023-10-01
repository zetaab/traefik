package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	common "github.com/elisasre/go-common"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/ip"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"golang.org/x/oauth2"
)

const (
	oidcTypeName = "oidcAuth"
	session      = "tsession"
	nextURI      = "next"
	state        = "state"
	callback     = "/_callback"
)

type oidcAuth struct {
	next           http.Handler
	config         *oauth2.Config
	provider       *oidc.Provider
	name           string
	checker        *ip.Checker
	strategy       ip.RemoteAddrStrategy
	forwardHeaders map[string]string
	acl            dynamic.ACL
}

// NewOidc creates a oidc auth middleware.
func NewOidc(ctx context.Context, next http.Handler, authConfig dynamic.OidcAuth, name string) (http.Handler, error) {
	provider, err := oidc.NewProvider(ctx, authConfig.Issuer)
	if err != nil {
		return nil, err
	}

	if authConfig.ACL.Allow != nil && authConfig.ACL.Deny != nil {
		return nil, fmt.Errorf("acl deny and allow cannot be both set")
	}

	oa := &oidcAuth{
		next:     next,
		name:     name,
		provider: provider,
		config: &oauth2.Config{
			ClientID:     authConfig.ClientID,
			ClientSecret: authConfig.ClientSecret,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     provider.Endpoint(),
		},
		strategy:       ip.RemoteAddrStrategy{},
		forwardHeaders: authConfig.ForwardHeaders,
		acl:            authConfig.ACL,
	}
	if len(authConfig.WhitelistIPs) > 0 {
		oa.checker, err = ip.NewChecker(authConfig.WhitelistIPs)
		if err != nil {
			return nil, fmt.Errorf("cannot parse CIDRs %s: %w", authConfig.WhitelistIPs, err)
		}
	}
	return oa, nil
}

func (o *oidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), o.name, oidcTypeName)

	clientIP := o.strategy.GetIP(req)
	if o.checker != nil {
		err := o.checker.IsAuthorized(clientIP)
		if err == nil {
			o.next.ServeHTTP(rw, req)
			return
		}
	}

	if req.URL.Path == callback {
		o.handleCallback(rw, req)
		return
	}

	// check do we have valid jwt as cookie, if not always fallback to login
	sessionCookie, err := req.Cookie(session)
	if sessionCookie == nil || err != nil {
		if err != nil {
			logger.Error().Msgf("got error while reading cookie: %v", err)
		}
		o.forwardToLogin(rw, req)
		return
	}
	user, err := o.parseJWTClaims(req, sessionCookie.Value)
	if err != nil || user == nil {
		if err != nil {
			logger.Error().Msgf("got error while parsing user: %v", err)
		}
		o.forwardToLogin(rw, req)
		return
	}

	grps := user.Groups
	if len(grps) == 0 {
		grps = user.ImportGroups
	}

	for k, v := range o.forwardHeaders {
		realValue := ""
		switch value := strings.ToLower(v); value {
		case "groups":
			realValue = strings.Join(grps, ",")
		case "email":
			realValue = common.PtrValue(user.Email)
		case "name":
			realValue = common.PtrValue(user.Name)
		case "employeeid":
			realValue = user.Eid
		default:
			// noop
		}
		if realValue != "" {
			req.Header.Set(k, realValue)
		}
	}

	err = checkACL(o.acl, grps)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}

	o.next.ServeHTTP(rw, req)
}

func checkACL(acl dynamic.ACL, grps []string) error {
	if acl.Allow != nil {
		allow := false
		for _, allowGroup := range acl.Allow {
			if slices.Contains(grps, allowGroup) {
				allow = true
				break
			}
		}
		if !allow {
			return fmt.Errorf("access denied")
		}
	} else if acl.Deny != nil {
		for _, denyGroup := range acl.Deny {
			if slices.Contains(grps, denyGroup) {
				return fmt.Errorf("access denied")
			}
		}
	}
	return nil
}

func (o *oidcAuth) parseJWTClaims(req *http.Request, value string) (*common.User, error) {
	verifier := o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID})
	idToken, err := verifier.Verify(req.Context(), value) // TODO: decrypt?
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims json.RawMessage
	err = idToken.Claims(&claims)
	if err != nil {
		return nil, err
	}
	dat := &common.User{}
	if err := json.Unmarshal(claims, &dat); err != nil {
		return nil, err
	}
	return dat, nil
}

func (o *oidcAuth) forwardToLogin(rw http.ResponseWriter, req *http.Request) {
	stateToken, err := common.RandomString(32)
	if err != nil {
		returnErr(rw, fmt.Errorf("failed to generate state token: %w", err))
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     state,
		Value:    stateToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Domain:   req.Host,
		MaxAge:   3600,
	})

	http.SetCookie(rw, &http.Cookie{
		Name:     nextURI,
		Value:    req.URL.RequestURI(),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Domain:   req.Host,
		MaxAge:   3600,
	})
	o.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, callback)
	authCodeURL := o.config.AuthCodeURL(stateToken, oauth2.AccessTypeOnline)
	http.Redirect(rw, req, authCodeURL, http.StatusSeeOther)
}

func (o *oidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		returnErr(rw, fmt.Errorf("unable to parse form %w", err))
		return
	}

	content := callbackContent{
		Code:  req.FormValue("code"),
		State: req.FormValue("state"),
	}

	stateToken, err := req.Cookie("state")
	if err != nil {
		returnErr(rw, fmt.Errorf("state cookie not found"))
		return
	}

	if content.State != stateToken.Value {
		returnErr(rw, fmt.Errorf("state did not match"))
		return
	}

	if content.Code == "" || content.State == "" {
		returnErr(rw, fmt.Errorf("code or state missing"))
		return
	}

	o.config.RedirectURL = fmt.Sprintf("https://%s%s", req.Host, callback)
	token, err := o.config.Exchange(req.Context(), content.Code)
	if err != nil {
		returnErr(rw, fmt.Errorf("unable to exchange token %w", err))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		returnErr(rw, fmt.Errorf("no id_token in token response"))
		return
	}

	verifier := o.provider.Verifier(&oidc.Config{ClientID: o.config.ClientID})
	_, err = verifier.Verify(req.Context(), rawIDToken)
	if err != nil {
		returnErr(rw, fmt.Errorf("failed to verify ID token: %w", err))
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     session, // TODO: encrypt?
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Domain:   req.Host,
		MaxAge:   3600 * 12, // should not be longer than oidc app session
	})

	clearCookie(rw, req, nextURI)
	clearCookie(rw, req, state)

	data, err := req.Cookie(nextURI)
	path := fmt.Sprintf("https://%s", req.Host)
	if err == nil && data != nil {
		path = fmt.Sprintf("https://%s%s", req.Host, data.Value)
	}
	http.Redirect(rw, req, path, http.StatusSeeOther)
}

type callbackContent struct {
	Code  string
	State string
}

func clearCookie(rw http.ResponseWriter, req *http.Request, cookieName string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Domain:   req.Host,
		MaxAge:   -1,
	})
}

func returnErr(rw http.ResponseWriter, err error) {
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}
