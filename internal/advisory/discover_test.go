package advisory

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiscoverCSAFSourceUsesAMetadataURLDirectly(t *testing.T) {
	upstream := newFakeUpstream()
	source, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream),
		"https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// A caller who already knows the path should not cost a discovery request.
	if len(upstream.requests) != 0 {
		t.Errorf("discovery made %d requests for a URL it was handed", len(upstream.requests))
	}
	if source.ProviderMetadata != "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json" {
		t.Errorf("metadata URL = %q", source.ProviderMetadata)
	}
	// otscout cannot read a vendor's terms, so defaulting to yes would have the
	// project publishing data it has no right to.
	if source.Info().Redistributable {
		t.Error("a provider given on the command line must not be assumed redistributable")
	}
}

func TestDiscoverCSAFSourceReadsSecurityTxt(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://certvde.com/.well-known/security.txt",
		"Contact: mailto:info@certvde.com\n"+
			"Preferred-Languages: de,en\n"+
			"CSAF: https://certvde.csaf-tp.certvde.com/.well-known/csaf/provider-metadata.json\n")

	source, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream), "certvde.com")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// This is the mechanism the specification defines, and it is what keeps the
	// project from needing a code change every time a vendor moves its feed.
	if source.ProviderMetadata != "https://certvde.csaf-tp.certvde.com/.well-known/csaf/provider-metadata.json" {
		t.Errorf("metadata URL = %q", source.ProviderMetadata)
	}
}

func TestDiscoverCSAFSourceRefusesASecurityTxtPointingAtAnotherSite(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://vendor.example/.well-known/security.txt",
		"CSAF: https://attacker.example/.well-known/csaf/provider-metadata.json\n")
	upstream.serve("https://vendor.example/.well-known/csaf/provider-metadata.json",
		`{"publisher": {"name": "Vendor"}, "distributions": []}`)

	source, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream), "vendor.example")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// A vendor domain is third party input. Following its security.txt to an
	// unrelated host would let whoever controls that file aim otscout anywhere.
	if strings.Contains(source.ProviderMetadata, "attacker.example") {
		t.Fatalf("discovery followed the file off site to %q", source.ProviderMetadata)
	}
	if source.ProviderMetadata != "https://vendor.example/.well-known/csaf/provider-metadata.json" {
		t.Errorf("metadata URL = %q, want the well-known fallback", source.ProviderMetadata)
	}
}

func TestDiscoverCSAFSourceAcceptsASubdomainOfTheSameSite(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://www.vendor.example/.well-known/security.txt",
		"CSAF: https://csaf.vendor.example/.well-known/csaf/provider-metadata.json\n")

	source, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream), "www.vendor.example")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// Vendors legitimately put the feed on a subdomain, which is why the test is
	// a suffix match on the domain rather than an exact host match.
	if source.ProviderMetadata != "https://csaf.vendor.example/.well-known/csaf/provider-metadata.json" {
		t.Errorf("metadata URL = %q", source.ProviderMetadata)
	}
}

func TestDiscoverCSAFSourceFallsBackToTheWellKnownPath(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://vendor.example/.well-known/csaf/provider-metadata.json",
		`{"publisher": {"name": "Vendor"}, "distributions": []}`)

	source, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream), "https://vendor.example")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if source.ProviderMetadata != "https://vendor.example/.well-known/csaf/provider-metadata.json" {
		t.Errorf("metadata URL = %q", source.ProviderMetadata)
	}
}

func TestDiscoverCSAFSourceSaysWhenAVendorAnswersWithAWebPage(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://vendor.example/.well-known/csaf/provider-metadata.json",
		"<!DOCTYPE html>\n<html lang=\"en\"><head><title>Not found</title></head></html>")

	_, err := DiscoverCSAFSource(context.Background(), testFetcher(t, upstream), "vendor.example")
	if err == nil {
		t.Fatal("a web page is not CSAF metadata and should be refused")
	}
	// Several vendors answer a missing CSAF path with their ordinary site and an
	// HTTP 200. A JSON syntax error would send the reader hunting the wrong thing.
	if !strings.Contains(err.Error(), "web page") {
		t.Errorf("error = %v", err)
	}
}

func TestDiscoverCSAFSourceReportsAVendorThatPublishesNothing(t *testing.T) {
	_, err := DiscoverCSAFSource(context.Background(), testFetcher(t, newFakeUpstream()), "vendor.example")
	if err == nil {
		t.Fatal("expected an error for a vendor with no CSAF feed")
	}
	if !strings.Contains(err.Error(), "security.txt") {
		t.Errorf("the error should say where discovery looked, got %v", err)
	}
}

func TestSourceFileNameStaysInsideTheAdvisoriesDirectory(t *testing.T) {
	// A discovered source id is built from something an operator typed, so these
	// are the shapes that would turn a corpus write into a write anywhere on disk.
	hostile := []string{
		"../../etc/passwd",
		"..",
		"csaf:host",
		`c:\windows\system32`,
		"source/../../..",
		"",
	}
	for _, id := range hostile {
		name := sourceFileName(id)
		if name == "" {
			t.Errorf("id %q produced an empty filename", id)
			continue
		}
		if strings.ContainsAny(name, `/\:`) || strings.Contains(name, "..") {
			t.Errorf("id %q produced %q, which is not a single safe filename", id, name)
		}
		joined := filepath.Join("corpus", advisoriesDir, name+".jsonl")
		if !strings.HasPrefix(joined, filepath.Join("corpus", advisoriesDir)+string(filepath.Separator)) {
			t.Errorf("id %q escaped to %q", id, joined)
		}
	}
}

func TestSourceFileNameDoesNotCollapseTwoDifferentSources(t *testing.T) {
	// Sanitising alone would map both of these to the same file, and the second
	// source to be saved would silently erase the first.
	first := sourceFileName("csaf:vendor.example")
	second := sourceFileName("csaf-vendor.example")
	if first == second {
		t.Errorf("two distinct source ids share the filename %q", first)
	}
}

func TestSourceFileNameLeavesOrdinarySourceIDsAlone(t *testing.T) {
	// The built in ids are already safe, and appending a digest to them would
	// churn every filename in every existing corpus for no reason.
	for _, id := range []string{"cisa-csaf", "cisa-kev", "epss", "ics-advisory-project"} {
		if got := sourceFileName(id); got != id {
			t.Errorf("sourceFileName(%q) = %q, want it unchanged", id, got)
		}
	}
}

func TestSyncRefusesAMistypedProviderBeforeDownloadingAnything(t *testing.T) {
	upstream := newFakeUpstream()
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)

	_, err := Sync(context.Background(), SyncOptions{
		Dir:           t.TempDir(),
		SourceIDs:     []string{"cisa-kev"},
		CSAFProviders: []string{"nothing-here.example"},
		Transport:     upstream,
		Spacing:       time.Nanosecond,
	})
	if err == nil {
		t.Fatal("expected the mistyped provider to fail the run")
	}
	// Failing up front is what keeps a typo from surfacing halfway through a sync
	// that has already spent ten minutes downloading.
	if upstream.count(kev.(*KEVSource).URL) != 0 {
		t.Error("the sync started downloading before validating the provider")
	}
}
