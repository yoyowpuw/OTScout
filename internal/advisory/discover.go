package advisory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// The CSAF specification defines how to find a provider without being told the
// exact path: ask the vendor's security.txt, or fall back to the well-known URL.
// Supporting that is what keeps this project from needing a code change every time
// a vendor reorganises its site, which the built in Siemens and Schneider entries
// have both already done once.
//
// Discovery only ever reads from the domain it was given. A security.txt that
// names a CSAF endpoint on some other host is not followed, because a vendor
// domain is third party input and following it would let whoever controls that
// file aim otscout at anything.

// DiscoverCSAFSource builds a source for a provider named by URL or by domain.
//
// A full provider-metadata.json URL is used directly. A bare domain is resolved
// through security.txt and then through the well-known path.
func DiscoverCSAFSource(ctx context.Context, fetcher *Fetcher, target string) (*CSAFSource, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("no CSAF provider given")
	}

	if strings.HasSuffix(strings.ToLower(target), ".json") {
		if err := validateURL(target); err != nil {
			return nil, err
		}
		return csafSourceFor(target), nil
	}

	host, err := providerHost(target)
	if err != nil {
		return nil, err
	}

	securityTxt := "https://" + host + "/.well-known/security.txt"
	if body, _, err := fetcher.Get(ctx, securityTxt); err == nil {
		if found, ok := csafFromSecurityTxt(string(body), host); ok {
			return csafSourceFor(found), nil
		}
	}

	// No security.txt, or none that names a CSAF endpoint. The well-known path is
	// what the specification requires a provider to serve, so it is worth trying
	// even though several vendors do not.
	wellKnown := "https://" + host + "/.well-known/csaf/provider-metadata.json"
	body, _, err := fetcher.Get(ctx, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("no CSAF provider found for %s: neither its security.txt nor %s named one",
			host, wellKnown)
	}
	if looksLikeHTML(body) {
		return nil, fmt.Errorf("%s answered with a web page rather than CSAF metadata, "+
			"so pass the provider-metadata.json URL directly", wellKnown)
	}
	return csafSourceFor(wellKnown), nil
}

// providerHost reduces whatever the operator typed to a host.
func providerHost(target string) (string, error) {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("bad CSAF provider %q: %w", target, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("CSAF provider %q names no host", target)
	}
	return parsed.Host, nil
}

// csafFromSecurityTxt reads the CSAF field, which is how a vendor publishes where
// its advisories live.
func csafFromSecurityTxt(body, host string) (string, bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "CSAF") {
			continue
		}
		candidate := strings.TrimSpace(value)
		if err := validateURL(candidate); err != nil {
			continue
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		// The endpoint has to be on the domain that published the file. Vendors
		// legitimately put it on a subdomain, as CERT@VDE does, so a suffix match
		// is the right test rather than an exact one.
		if !sameSite(parsed.Host, host) {
			continue
		}
		return candidate, true
	}
	return "", false
}

// sameSite reports whether one host belongs to the other's domain.
func sameSite(candidate, host string) bool {
	candidate, host = strings.ToLower(candidate), strings.ToLower(host)
	if candidate == host {
		return true
	}
	base := strings.TrimPrefix(host, "www.")
	return strings.HasSuffix(candidate, "."+base) || candidate == base
}

// csafSourceFor builds an unregistered source for a discovered provider.
//
// It is deliberately marked as not redistributable. otscout has no way to read a
// vendor's terms, and defaulting to yes would have the project publishing data it
// has no right to.
func csafSourceFor(metadataURL string) *CSAFSource {
	host, _ := providerHost(metadataURL)
	return &CSAFSource{
		ProviderMetadata: metadataURL,
		Meta: Info{
			ID:              "csaf-" + host,
			Name:            "CSAF provider at " + host,
			Kind:            KindAdvisories,
			Homepage:        "https://" + host + "/",
			License:         "unknown, check this vendor's terms before redistributing",
			Redistributable: false,
			Summary:         "A CSAF provider given on the command line rather than built in.",
		},
	}
}
