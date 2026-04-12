package charon

// File should not be named license* or notice* so that it is not detected as legal text by various tooling.

import (
	"bytes"
	"net/http"
	"strconv"
	"time"

	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/waf"
)

// LicenseGet is the frontend handler for the LICENSE file.
func (s *Service) LicenseGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		// This really serves the LICENSE file from the root directory and not /public/LICENSE.txt,
		// but that is fine, they are the same (they are symlinked).
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/LICENSE.txt")
	}
}

// NoticeGet is the frontend handler for the NOTICE file.
func (s *Service) NoticeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		// rollup-plugin-license does not make the file available during development,
		// so we just return empty response.
		w.WriteHeader(http.StatusOK)
	} else {
		s.ServeStaticFile(w, req, "/NOTICE.txt")
	}
}

// TermsOfServiceGet is the frontend handler for the "terms of service" page.
func (s *Service) TermsOfServiceGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// TermsOfServiceGetAPI is the API handler for the "terms of service" page.
func (s *Service) TermsOfServiceGetAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.termsOfService)))
	w.Header().Set("Etag", x.ComputeEtag(s.termsOfService))
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(s.termsOfService))
}

// PrivacyPolicyGet is the frontend handler for the "privacy policy" page.
func (s *Service) PrivacyPolicyGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	if s.ProxyStaticTo != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

// PrivacyPolicyGetAPI is the API handler for the "privacy policy" page.
func (s *Service) PrivacyPolicyGetAPI(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.privacyPolicy)))
	w.Header().Set("Etag", x.ComputeEtag(s.privacyPolicy))
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(s.privacyPolicy))
}
