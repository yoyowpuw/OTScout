package advisory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUpstream serves fixtures in place of the real feeds. Every source has a
// hardcoded URL because those URLs are part of what the project promises, so the
// tests intercept at the transport rather than rewriting the URLs.
type fakeUpstream struct {
	mu       sync.Mutex
	routes   map[string]fakeResponse
	requests []string
	// etag, when set, makes the server answer 304 to a conditional request, which
	// is how the caching path is exercised.
	etag string
}

type fakeResponse struct {
	status  int
	body    []byte
	headers map[string]string
}

func newFakeUpstream() *fakeUpstream {
	return &fakeUpstream{routes: make(map[string]fakeResponse)}
}

func (f *fakeUpstream) serve(url string, body string) {
	f.routes[url] = fakeResponse{status: http.StatusOK, body: []byte(body)}
}

func (f *fakeUpstream) serveBytes(url string, body []byte) {
	f.routes[url] = fakeResponse{status: http.StatusOK, body: body}
}

func (f *fakeUpstream) fail(url string, status int) {
	f.routes[url] = fakeResponse{status: status}
}

func (f *fakeUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req.URL.String())
	route, ok := f.routes[req.URL.String()]
	etag := f.etag
	f.mu.Unlock()

	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	header := make(http.Header)
	for name, value := range route.headers {
		header.Set(name, value)
	}
	if etag != "" {
		header.Set("ETag", etag)
		if req.Header.Get("If-None-Match") == etag {
			return &http.Response{
				StatusCode: http.StatusNotModified,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     header,
				Request:    req,
			}, nil
		}
	}
	return &http.Response{
		StatusCode: route.status,
		Body:       io.NopCloser(bytes.NewReader(route.body)),
		Header:     header,
		Request:    req,
	}, nil
}

func (f *fakeUpstream) count(url string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, seen := range f.requests {
		if seen == url {
			n++
		}
	}
	return n
}

func testFetcher(t *testing.T, upstream *fakeUpstream) *Fetcher {
	t.Helper()
	fetcher, err := NewFetcher(FetcherOptions{
		CacheDir:     t.TempDir(),
		Transport:    upstream,
		Spacing:      time.Nanosecond,
		RetryBackoff: time.Nanosecond,
		Retries:      1,
	})
	if err != nil {
		t.Fatalf("build fetcher: %v", err)
	}
	return fetcher
}

func testEnv(t *testing.T, upstream *fakeUpstream) *Env {
	t.Helper()
	return &Env{Fetcher: testFetcher(t, upstream)}
}

const cisaMetadataURL = "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"

func cisaProviderMetadata(feedURL string) string {
	return fmt.Sprintf(`{
      "canonical_url": %q,
      "publisher": {"category": "coordinator", "name": "CISA"},
      "distributions": [
        {"directory_url": "https://www.cisa.gov/csaf/", "rolie": {"feeds": [
          {"summary": "public", "tlp_label": "WHITE", "url": %q}
        ]}}
      ]
    }`, cisaMetadataURL, feedURL)
}

func rolieFeedJSON(entries ...string) string {
	return fmt.Sprintf(`{"feed": {"id": "public", "title": "CISA", "updated": "2026-03-01T00:00:00Z", "entry": [%s]}}`,
		strings.Join(entries, ","))
}

func rolieEntry(id, url, updated string) string {
	return fmt.Sprintf(`{"id": %q, "title": %q, "updated": %q, "format": {"schema": "csaf", "version": "2.0"},
      "link": [{"rel": "self", "href": %q}]}`, id, id, updated, url)
}

func csafAdvisory(id, vendor, product, version, cve string) string {
	return fmt.Sprintf(`{
      "document": {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "title": %q,
        "publisher": {"category": "coordinator", "name": "CISA"},
        "tracking": {"id": %q, "status": "final", "version": "1.0",
          "initial_release_date": "2026-01-05T00:00:00Z",
          "current_release_date": "2026-01-05T00:00:00Z"}
      },
      "product_tree": {"branches": [
        {"category": "vendor", "name": %q, "branches": [
          {"category": "product_name", "name": %q, "branches": [
            {"category": "product_version", "name": %q, "product": {"product_id": "p1", "name": %q}}
          ]}
        ]}
      ]},
      "vulnerabilities": [{"cve": %q, "product_status": {"known_affected": ["p1"]},
        "scores": [{"products": ["p1"], "cvss_v3": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}]
    }`, id, id, vendor, product, version, product, cve)
}

func TestCSAFSourceWalksTheROLIEFeedAndReadsEveryAdvisory(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed-tlp-white.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-010-01", "https://www.cisa.gov/csaf/2026/icsa-26-010-01.json", "2026-01-10T00:00:00Z"),
		rolieEntry("ICSA-26-011-01", "https://www.cisa.gov/csaf/2026/icsa-26-011-01.json", "2026-01-11T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/2026/icsa-26-010-01.json",
		csafAdvisory("ICSA-26-010-01", "Siemens", "SIMATIC S7-1200", "V4.4", "CVE-2026-1001"))
	upstream.serve("https://www.cisa.gov/csaf/2026/icsa-26-011-01.json",
		csafAdvisory("ICSA-26-011-01", "Rockwell Automation", "ControlLogix 1756-L71", "V32.011", "CVE-2026-1002"))

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	if len(result.Advisories) != 2 {
		t.Fatalf("got %d advisories, want 2", len(result.Advisories))
	}
	if result.Advisories[0].Source != "cisa-csaf" {
		t.Errorf("source = %q", result.Advisories[0].Source)
	}
	// The document itself carries no self reference, so the URL it was fetched
	// from stands in. An operator has to be able to click through to the original.
	if result.Advisories[0].URL == "" {
		t.Error("an advisory with no self reference should fall back to its fetch URL")
	}
}

func TestCSAFSourceSkipsEntriesThatHaveNotChangedSinceTheLastSync(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed-tlp-white.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-001-01", "https://www.cisa.gov/csaf/2026/old.json", "2026-01-01T00:00:00Z"),
		rolieEntry("ICSA-26-020-01", "https://www.cisa.gov/csaf/2026/new.json", "2026-02-20T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/2026/old.json",
		csafAdvisory("ICSA-26-001-01", "Moxa", "EDS-405A", "V3.9", "CVE-2026-1"))
	upstream.serve("https://www.cisa.gov/csaf/2026/new.json",
		csafAdvisory("ICSA-26-020-01", "Moxa", "EDS-408A", "V3.9", "CVE-2026-2"))

	env := testEnv(t, upstream)
	env.Since = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), env)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	// The whole point of the feed timestamp is that an unchanged document is not
	// downloaded at all. Refetching several thousand documents daily is what gets
	// a project blocked by an upstream.
	if upstream.count("https://www.cisa.gov/csaf/2026/old.json") != 0 {
		t.Error("an entry older than the cutoff should not have been fetched")
	}
	if len(result.Advisories) != 1 || result.Advisories[0].ID != "ICSA-26-020-01" {
		t.Errorf("got %d advisories, want only the changed one", len(result.Advisories))
	}
}

func TestCSAFSourceIgnoresFeedsThatAreNotPublic(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, `{
      "publisher": {"name": "CISA"},
      "distributions": [{"rolie": {"feeds": [
        {"summary": "restricted", "tlp_label": "AMBER", "url": "https://www.cisa.gov/csaf/feed-amber.json"}
      ]}}]
    }`)

	source, _ := SourceByID("cisa-csaf")
	_, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err == nil {
		t.Fatal("expected the sync to report that nothing was listed")
	}
	// An amber feed needs credentials otscout does not have and should not be
	// asking for, so it must not even be requested.
	if upstream.count("https://www.cisa.gov/csaf/feed-amber.json") != 0 {
		t.Error("a restricted feed should not be fetched")
	}
}

func TestCSAFSourceFallsBackToTheDirectoryIndexWhenThereIsNoFeed(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, `{
      "publisher": {"name": "CISA"},
      "distributions": [{"directory_url": "https://www.cisa.gov/csaf/"}]
    }`)
	upstream.serve("https://www.cisa.gov/csaf/index.txt",
		"2026/icsa-26-030-01.json\n\n# a comment\n2026/icsa-26-031-01.json\n")
	upstream.serve("https://www.cisa.gov/csaf/2026/icsa-26-030-01.json",
		csafAdvisory("ICSA-26-030-01", "ABB", "AC 800M", "6.0", "CVE-2026-3"))
	upstream.serve("https://www.cisa.gov/csaf/2026/icsa-26-031-01.json",
		csafAdvisory("ICSA-26-031-01", "ABB", "AC 500", "2.8", "CVE-2026-4"))

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.Advisories) != 2 {
		t.Fatalf("got %d advisories from the index, want 2", len(result.Advisories))
	}
}

func TestCSAFSourceRefusesToFollowAFeedToAnotherHost(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata("https://www.cisa.gov/csaf/feed.json"))
	upstream.serve("https://www.cisa.gov/csaf/feed.json", rolieFeedJSON(
		rolieEntry("evil", "https://attacker.example/payload.json", "2026-01-01T00:00:00Z"),
		rolieEntry("ICSA-26-040-01", "https://www.cisa.gov/csaf/2026/ok.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/2026/ok.json",
		csafAdvisory("ICSA-26-040-01", "Hitachi Energy", "RTU500", "12.0", "CVE-2026-5"))

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// A vendor feed is third party input. Letting one redirect the fetcher at an
	// arbitrary host turns sync into a probe tool for whoever controls the feed.
	if upstream.count("https://attacker.example/payload.json") != 0 {
		t.Fatal("the fetcher followed a feed entry to another host")
	}
	if len(result.Advisories) != 1 {
		t.Errorf("got %d advisories, the legitimate entry should still be read", len(result.Advisories))
	}
	if len(result.Warnings) == 0 {
		t.Error("the rejected entry should be recorded as a warning")
	}
}

func TestCSAFSourceFollowsTheHostsItsDefinitionNames(t *testing.T) {
	// CISA publishes its metadata on cisa.gov and its documents on GitHub. The
	// second host is named in the source definition, so it is fixed in the binary
	// rather than being whatever the feed asks for.
	const feedURL = "https://raw.githubusercontent.com/cisagov/CSAF/develop/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-045-01",
			"https://raw.githubusercontent.com/cisagov/CSAF/develop/2026/icsa-26-045-01.json",
			"2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://raw.githubusercontent.com/cisagov/CSAF/develop/2026/icsa-26-045-01.json",
		csafAdvisory("ICSA-26-045-01", "Mitsubishi Electric", "MELSEC iQ-R", "1.050", "CVE-2026-7"))

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.Advisories) != 1 {
		t.Fatalf("got %d advisories, want the document from the named host", len(result.Advisories))
	}
}

func TestCSAFSourceKeepsGoingWhenOneDocumentIsBroken(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("broken", "https://www.cisa.gov/csaf/broken.json", "2026-01-01T00:00:00Z"),
		rolieEntry("missing", "https://www.cisa.gov/csaf/missing.json", "2026-01-01T00:00:00Z"),
		rolieEntry("ICSA-26-050-01", "https://www.cisa.gov/csaf/good.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/broken.json", `{"document": not json`)
	upstream.fail("https://www.cisa.gov/csaf/missing.json", http.StatusNotFound)
	upstream.serve("https://www.cisa.gov/csaf/good.json",
		csafAdvisory("ICSA-26-050-01", "Schneider Electric", "Modicon M340", "3.40", "CVE-2026-6"))

	source, _ := SourceByID("cisa-csaf")
	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// One bad document out of several thousand is normal. Failing the whole sync
	// over it would leave a site with no corpus at all.
	if len(result.Advisories) != 1 {
		t.Fatalf("got %d advisories, want the one good document", len(result.Advisories))
	}
	if len(result.Warnings) < 2 {
		t.Errorf("both failures should be recorded, got %v", result.Warnings)
	}
}

const kevFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.03.01",
  "dateReleased": "2026-03-01T12:00:00.0000Z",
  "count": 3,
  "vulnerabilities": [
    {"cveID": "CVE-2026-1001", "vendorProject": "Siemens", "product": "SIMATIC",
     "vulnerabilityName": "Siemens SIMATIC Improper Input Validation",
     "dateAdded": "2026-02-01", "shortDescription": "A flaw.",
     "requiredAction": "Apply mitigations per vendor instructions.",
     "dueDate": "2026-02-22", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-1002", "vendorProject": "Rockwell", "product": "ControlLogix",
     "vulnerabilityName": "Rockwell ControlLogix Denial of Service",
     "dateAdded": "2026-02-05", "dueDate": "2026-02-26",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "not-a-cve", "vendorProject": "Junk", "product": "Junk", "dateAdded": "2026-02-05"}
  ]
}`

func TestKEVSourceReadsTheCatalogueAndRefusesJunkIdentifiers(t *testing.T) {
	upstream := newFakeUpstream()
	source, _ := SourceByID("cisa-kev")
	upstream.serve(source.(*KEVSource).URL, kevFixture)

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.KEV) != 2 {
		t.Fatalf("got %d entries, want the two valid ones", len(result.KEV))
	}

	entry := result.KEV["CVE-2026-1001"]
	if !entry.KnownRansomware {
		t.Error("an entry marked Known for ransomware use should say so")
	}
	if entry.DueDate.Format("2006-01-02") != "2026-02-22" {
		t.Errorf("due date = %v", entry.DueDate)
	}
	if result.KEV["CVE-2026-1002"].KnownRansomware {
		t.Error("an entry marked Unknown must not report ransomware use")
	}
	// A malformed identifier would become a map key that silently never matches
	// anything, which is worse than dropping the row.
	if _, present := result.KEV["NOT-A-CVE"]; present {
		t.Error("a malformed identifier should not reach the corpus")
	}
}

func TestEPSSSourceReadsTheGzippedCSV(t *testing.T) {
	csv := "#model_version:v2026.03.01,score_date:2026-03-04T00:00:00+0000\n" +
		"cve,epss,percentile\n" +
		"CVE-2026-1001,0.97250,0.99900\n" +
		"CVE-2026-1002,0.00042,0.05100\n" +
		"garbage,0.5,0.5\n"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(csv)); err != nil {
		t.Fatalf("compress fixture: %v", err)
	}
	gz.Close()

	upstream := newFakeUpstream()
	source, _ := SourceByID("epss")
	upstream.serveBytes(source.(*EPSSSource).URL, buf.Bytes())

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.EPSS) != 2 {
		t.Fatalf("got %d scores, want 2", len(result.EPSS))
	}
	if got := result.EPSS["CVE-2026-1001"].Score; got != 0.97250 {
		t.Errorf("score = %v", got)
	}
	// The model date tells an operator whether the corpus they are triaging from
	// is a week old or a year old.
	if date := result.EPSS["CVE-2026-1001"].ModelDate.Format("2006-01-02"); date != "2026-03-04" {
		t.Errorf("model date = %q", date)
	}
}

func TestEPSSSourceReadsThePlainCSVWhenTheTransportAlreadyDecompressed(t *testing.T) {
	csv := "#model_version:v2026.03.01,score_date:2026-03-04T00:00:00+0000\n" +
		"cve,epss,percentile\nCVE-2026-2001,0.5,0.9\n"

	upstream := newFakeUpstream()
	source, _ := SourceByID("epss")
	upstream.serve(source.(*EPSSSource).URL, csv)

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.EPSS) != 1 {
		t.Fatalf("got %d scores", len(result.EPSS))
	}
}

// The header and rows below are the shape the project actually ships, taken from
// the live file rather than guessed at.
const icsapCSV = `icsad_ID,Original_Release_Date,Last_Updated,Year,ICS-CERT_Number,ICS-CERT_Advisory_Title,Vendor,Product,Products_Affected,CVE_Number,Cumulative_CVSS,CVSS_Severity,CWE_Number,Critical_Infrastructure_Sector,Product_Distribution,Company_Headquarters,License
1,3/1/2026,3/1/2026,2026,ICSA-26-060-01,Siemens SIMATIC,Siemens,Siemens SIMATIC,SIMATIC S7-1500 <=V2.9.2 | SIMATIC S7-1200 <V4.5,"CVE-2026-3001, CVE-2026-3002",9.8,Critical,CWE-787,Energy,Worldwide,Germany,ODbL v1.0
2,3/1/2026,3/1/2026,2026,ICSA-26-060-01,Siemens SIMATIC,Moxa,Moxa EDS,EDS-405A,CVE-2026-3003,9.8,Critical,CWE-787,Energy,Worldwide,Taiwan,ODbL v1.0
3,3/2/2026,3/2/2026,2026,ICSA-26-060-02,Rockwell ControlLogix,Rockwell Automation,Rockwell ControlLogix,ControlLogix 5580 >=V36|<=V37 | 1756-EN4TR V6.001,CVE-2026-3004,7.5,High,CWE-20,Manufacturing,Worldwide,USA,ODbL v1.0
`

func TestICSAPSourceGathersTheRowsOfOneAdvisoryTogether(t *testing.T) {
	upstream := newFakeUpstream()
	source, _ := SourceByID("ics-advisory-project")
	upstream.serve(source.(*ICSAPSource).URL, icsapCSV)

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.Advisories) != 2 {
		t.Fatalf("got %d advisories from 3 rows, want 2", len(result.Advisories))
	}

	first := result.Advisories[0]
	if first.ID != "ICSA-26-060-01" {
		t.Fatalf("first advisory = %q", first.ID)
	}
	// One advisory spans two rows here because it covers two vendors, which is
	// exactly why rows have to accumulate rather than replace.
	if len(first.Products) != 3 {
		t.Fatalf("got %d products, want two from the first row and one from the second: %+v",
			len(first.Products), first.Products)
	}
	if first.Products[0].ProductRaw != "SIMATIC S7-1500" || first.Products[0].VersionRaw != "<=V2.9.2" {
		t.Errorf("first product = %q version %q", first.Products[0].ProductRaw, first.Products[0].VersionRaw)
	}
	if first.Products[2].VendorRaw != "Moxa" {
		t.Errorf("the second row's vendor = %q, want Moxa", first.Products[2].VendorRaw)
	}

	// Three distinct CVEs across the two rows, none repeated.
	if len(first.Vulnerabilities) != 3 {
		t.Fatalf("got %d vulnerabilities, want 3", len(first.Vulnerabilities))
	}
	// The CSV carries no per product status, so every product is affected by
	// every CVE. Recording that explicitly keeps the matcher from having to guess.
	affected, explicit := first.Vulnerabilities[0].AffectedProducts()
	if !explicit || len(affected) != 3 {
		t.Errorf("affected products = %v, want all three", affected)
	}
	if score, ok := first.Vulnerabilities[0].BestScore(); !ok || score.BaseScore != 9.8 {
		t.Errorf("score = %+v", score)
	}
	if first.Vulnerabilities[0].CWEID != "CWE-787" {
		t.Errorf("cwe = %q", first.Vulnerabilities[0].CWEID)
	}
	// The file carries no link column, so the advisory number is turned into one.
	if first.URL != "https://www.cisa.gov/news-events/ics-advisories/icsa-26-060-01" {
		t.Errorf("url = %q", first.URL)
	}
}

func TestICSAPSourceDoesNotTearAVersionRangeInHalfAtItsPipe(t *testing.T) {
	upstream := newFakeUpstream()
	source, _ := SourceByID("ics-advisory-project")
	upstream.serve(source.(*ICSAPSource).URL, icsapCSV)

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	second := result.Advisories[1]
	if len(second.Products) != 2 {
		t.Fatalf("got %d products: %+v", len(second.Products), second.Products)
	}
	// The cell reads "ControlLogix 5580 >=V36|<=V37 | 1756-EN4TR V6.001". A bare
	// pipe joins the two halves of one range, and only a spaced pipe separates
	// products. Splitting on the wrong one invents a product called "<=V37".
	if second.Products[0].ProductRaw != "ControlLogix 5580" {
		t.Errorf("first product = %q", second.Products[0].ProductRaw)
	}
	if second.Products[0].VersionRaw != ">=V36|<=V37" {
		t.Errorf("first version = %q, want the whole range", second.Products[0].VersionRaw)
	}
	// "1756-EN4TR V6.001" has no comparison operator, so it stays whole. Reading
	// the trailing token as a version would be a guess, and ICS product names are
	// full of model numbers that look exactly like versions.
	if second.Products[1].ProductRaw != "1756-EN4TR V6.001" {
		t.Errorf("second product = %q, want the model number left intact", second.Products[1].ProductRaw)
	}
	if second.Products[1].VersionRaw != "" {
		t.Errorf("second version = %q, want none guessed", second.Products[1].VersionRaw)
	}
}

func TestICSAPSourceAcceptsTheColumnNamesTheProjectHasUsedOverTime(t *testing.T) {
	// The project has renamed columns between releases. Accepting the spellings
	// it has actually shipped keeps a rename from silently emptying the corpus.
	csv := "Advisory_Number,Vendor Name,Affected Products,CVEs,CVSS v3 Score\n" +
		"ICSA-26-070-01,Moxa,EDS-405A <3.9,CVE-2026-4001,6.5\n"

	upstream := newFakeUpstream()
	source, _ := SourceByID("ics-advisory-project")
	upstream.serve(source.(*ICSAPSource).URL, csv)

	result, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(result.Advisories) != 1 {
		t.Fatalf("got %d advisories", len(result.Advisories))
	}
	product := result.Advisories[0].Products[0]
	if product.VendorRaw != "Moxa" || product.VersionRaw != "<3.9" {
		t.Errorf("product = %+v", product)
	}
}

func TestICSAPSourceRefusesAFileWhoseFormatChangedBeyondRecognition(t *testing.T) {
	upstream := newFakeUpstream()
	source, _ := SourceByID("ics-advisory-project")
	upstream.serve(source.(*ICSAPSource).URL, "alpha,beta,gamma\n1,2,3\n")

	_, err := source.Sync(context.Background(), testEnv(t, upstream))
	if err == nil {
		t.Fatal("a file with no recognisable columns should be refused rather than silently yielding nothing")
	}
	if !strings.Contains(err.Error(), "format has changed") {
		t.Errorf("error = %v", err)
	}
}

func TestNVDSourceOnlyLooksUpTheCVEsThatHaveNoScore(t *testing.T) {
	corpus := NewCorpus(t.TempDir())
	corpus.Advisories = []Advisory{{
		ID:     "ICSA-26-080-01",
		Source: "cisa-csaf",
		Vulnerabilities: []Vulnerability{
			{CVE: "CVE-2026-5001", Scores: []Score{{Version: "3.1", BaseScore: 7.5}}},
			{CVE: "CVE-2026-5002"},
		},
	}}

	unscored := UnscoredCVEs(corpus)
	if len(unscored) != 1 || unscored[0] != "CVE-2026-5002" {
		t.Fatalf("unscored = %v, want only the CVE with no score", unscored)
	}

	upstream := newFakeUpstream()
	upstream.serve(defaultNVDEndpoint+"?cveId=CVE-2026-5002", `{
      "resultsPerPage": 1, "totalResults": 1,
      "vulnerabilities": [{"cve": {
        "id": "CVE-2026-5002",
        "descriptions": [{"lang": "en", "value": "A stack overflow."}],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-121"}]}],
        "metrics": {"cvssMetricV31": [
          {"source": "nvd@nist.gov", "type": "Primary",
           "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 9.1, "baseSeverity": "CRITICAL"}},
          {"source": "vendor@example", "type": "Secondary",
           "cvssData": {"version": "3.1", "baseScore": 4.0, "baseSeverity": "MEDIUM"}}
        ]}
      }}]
    }`)

	source, _ := SourceByID("nvd")
	if _, err := source.(*NVDSource).EnrichCorpus(context.Background(), testEnv(t, upstream), corpus); err != nil {
		t.Fatalf("enrich: %v", err)
	}

	// The advisory's own score wins, because the vendor who wrote it knows the
	// product and NVD scores for ICS flaws are often assigned generically.
	if got := corpus.Advisories[0].Vulnerabilities[0].Scores[0].BaseScore; got != 7.5 {
		t.Errorf("an existing score was overwritten, got %v", got)
	}
	filled := corpus.Advisories[0].Vulnerabilities[1]
	if len(filled.Scores) != 1 {
		t.Fatalf("got %d scores, want only the primary one", len(filled.Scores))
	}
	if filled.Scores[0].BaseScore != 9.1 {
		t.Errorf("filled score = %v, want the primary scoring", filled.Scores[0].BaseScore)
	}
	if filled.CWEID != "CWE-121" {
		t.Errorf("cwe = %q", filled.CWEID)
	}
}

func TestNVDSourceRefusesToBeSyncedOnItsOwn(t *testing.T) {
	source, _ := SourceByID("nvd")
	if _, err := source.Sync(context.Background(), &Env{}); err == nil {
		t.Fatal("the NVD source has no feed of its own and should say so")
	}
}

func TestSyncWritesACorpusAndRecordsWhereEverythingCameFrom(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-090-01", "https://www.cisa.gov/csaf/a.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/a.json",
		csafAdvisory("ICSA-26-090-01", "Siemens", "SIMATIC S7-1500", "<V2.9.2", "CVE-2026-1001"))

	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)
	epss, _ := SourceByID("epss")
	upstream.serve(epss.(*EPSSSource).URL,
		"#model_version:v2026.03.01,score_date:2026-03-04T00:00:00+0000\ncve,epss,percentile\nCVE-2026-1001,0.9,0.99\n")

	dir := filepath.Join(t.TempDir(), "corpus")
	report, err := Sync(context.Background(), SyncOptions{
		Dir:          dir,
		Transport:    upstream,
		Spacing:      time.Nanosecond,
		RetryBackoff: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(report.Failed) != 0 {
		t.Fatalf("sources failed: %v", report.Failed)
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(corpus.Advisories) != 1 {
		t.Fatalf("got %d advisories after reload", len(corpus.Advisories))
	}

	adv := corpus.Advisories[0]
	// Normalization runs at sync time so that a match run never has to reparse
	// several thousand range strings.
	if adv.Products[0].Vendor != "siemens" {
		t.Errorf("vendor was not resolved at sync time: %q", adv.Products[0].Vendor)
	}
	// KEV and EPSS are stored separately and folded in at load time, so a
	// reloaded corpus has to come back with them attached.
	if !adv.HasKEV() {
		t.Error("the KEV entry was not attached after reload")
	}
	if adv.MaxEPSS() != 0.9 {
		t.Errorf("EPSS score after reload = %v", adv.MaxEPSS())
	}

	// The licence question has to be answerable later without guessing, which
	// means the answer is stored next to the data.
	for _, state := range corpus.Manifest.Sources {
		if state.License == "" {
			t.Errorf("source %s recorded no licence", state.ID)
		}
	}
}

func TestSyncKeepsTheOtherSourcesWhenOneFeedIsUnreachable(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.fail(cisaMetadataURL, http.StatusServiceUnavailable)
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)
	epss, _ := SourceByID("epss")
	upstream.serve(epss.(*EPSSSource).URL, "cve,epss,percentile\nCVE-2026-1001,0.9,0.99\n")

	dir := filepath.Join(t.TempDir(), "corpus")
	report, err := Sync(context.Background(), SyncOptions{
		Dir:          dir,
		Transport:    upstream,
		Spacing:      time.Nanosecond,
		RetryBackoff: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("sync should not abort over one unreachable feed: %v", err)
	}
	// A corpus that is mostly current is far more use than none at all, but the
	// operator has to be told which part is missing.
	if len(report.Failed) != 1 || report.Failed[0] != "cisa-csaf" {
		t.Errorf("failed sources = %v", report.Failed)
	}
	if len(report.Sources) != 3 {
		t.Errorf("got %d source states, want one per requested source", len(report.Sources))
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(corpus.KEV) == 0 {
		t.Error("the sources that did work should still have been written")
	}
	for _, state := range corpus.Manifest.Sources {
		if state.ID == "cisa-csaf" && state.Error == "" {
			t.Error("the failure should be recorded in the manifest")
		}
	}
}

func TestSyncDoesNotDropOneSourceWhenAnotherIsRefreshedAlone(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-100-01", "https://www.cisa.gov/csaf/a.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/a.json",
		csafAdvisory("ICSA-26-100-01", "ABB", "AC 800M", "6.0", "CVE-2026-1001"))
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)

	dir := filepath.Join(t.TempDir(), "corpus")
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, SourceIDs: []string{"cisa-csaf"}, Transport: upstream, Spacing: time.Nanosecond,
	}); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	// Refreshing KEV on its own is the common daily case. It must not take the
	// advisory corpus with it.
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, SourceIDs: []string{"cisa-kev"}, Transport: upstream, Spacing: time.Nanosecond,
	}); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(corpus.Advisories) != 1 {
		t.Fatalf("got %d advisories, the CISA corpus was dropped by a KEV refresh", len(corpus.Advisories))
	}
	if len(corpus.KEV) == 0 {
		t.Error("the KEV refresh did not land")
	}
}

func TestSyncWritesTheSameBytesWhenNothingChanged(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-110-01", "https://www.cisa.gov/csaf/a.json", "2026-01-01T00:00:00Z"),
		rolieEntry("ICSA-26-110-02", "https://www.cisa.gov/csaf/b.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/a.json",
		csafAdvisory("ICSA-26-110-01", "Siemens", "SIMATIC", "V1.0", "CVE-2026-1"))
	upstream.serve("https://www.cisa.gov/csaf/b.json",
		csafAdvisory("ICSA-26-110-02", "Moxa", "EDS-405A", "V2.0", "CVE-2026-2"))

	dir := filepath.Join(t.TempDir(), "corpus")
	opts := SyncOptions{Dir: dir, SourceIDs: []string{"cisa-csaf"}, Transport: upstream, Spacing: time.Nanosecond}

	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	path := filepath.Join(dir, advisoriesDir, "cisa-csaf.jsonl")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}

	if _, err := Sync(context.Background(), opts); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}

	// A corpus is meant to be committed and reviewed as a diff. A sync that
	// changed nothing has to produce identical bytes or every review is noise.
	if !bytes.Equal(before, after) {
		t.Error("syncing twice with no upstream change produced different bytes")
	}
}

func TestSyncStripsEnrichmentFromTheAdvisoryFileSoAKEVRefreshRewritesOneSmallFile(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-120-01", "https://www.cisa.gov/csaf/a.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/a.json",
		csafAdvisory("ICSA-26-120-01", "Siemens", "SIMATIC", "V1.0", "CVE-2026-1001"))
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)

	dir := filepath.Join(t.TempDir(), "corpus")
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, SourceIDs: []string{"cisa-csaf", "cisa-kev"}, Transport: upstream, Spacing: time.Nanosecond,
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, advisoriesDir, "cisa-csaf.jsonl"))
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}
	var stored Advisory
	if err := json.Unmarshal(bytes.TrimSpace(data), &stored); err != nil {
		t.Fatalf("parse stored advisory: %v", err)
	}
	// Enrichment is derived data held elsewhere in the corpus. Duplicating it
	// here would mean a KEV refresh rewrote every advisory file.
	if stored.Vulnerabilities[0].KEV != nil {
		t.Error("the advisory file should not carry a copy of the KEV entry")
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !corpus.Advisories[0].HasKEV() {
		t.Error("the KEV entry should be folded back in at load time")
	}
}

func TestSyncKeepsOnlyTheEnrichmentTheCorpusCanActuallyReach(t *testing.T) {
	const feedURL = "https://www.cisa.gov/csaf/feed.json"
	upstream := newFakeUpstream()
	upstream.serve(cisaMetadataURL, cisaProviderMetadata(feedURL))
	upstream.serve(feedURL, rolieFeedJSON(
		rolieEntry("ICSA-26-130-01", "https://www.cisa.gov/csaf/a.json", "2026-01-01T00:00:00Z"),
	))
	upstream.serve("https://www.cisa.gov/csaf/a.json",
		csafAdvisory("ICSA-26-130-01", "Siemens", "SIMATIC", "V1.0", "CVE-2026-1001"))
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)

	dir := filepath.Join(t.TempDir(), "corpus")
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, SourceIDs: []string{"cisa-csaf", "cisa-kev"}, Transport: upstream, Spacing: time.Nanosecond,
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	// The fixture holds two valid KEV entries but only one of them is named by an
	// advisory. Keeping the other would put data on the media that carries this
	// corpus into a plant that nothing can ever reach.
	if len(corpus.KEV) != 1 {
		t.Fatalf("stored %d KEV entries, want only the one an advisory mentions", len(corpus.KEV))
	}
	if _, ok := corpus.KEV["CVE-2026-1001"]; !ok {
		t.Error("the entry that is actually reachable was dropped")
	}
}

func TestSyncKeepsEnrichmentWhenNoAdvisoriesHaveArrivedYet(t *testing.T) {
	upstream := newFakeUpstream()
	kev, _ := SourceByID("cisa-kev")
	upstream.serve(kev.(*KEVSource).URL, kevFixture)

	dir := filepath.Join(t.TempDir(), "corpus")
	if _, err := Sync(context.Background(), SyncOptions{
		Dir: dir, SourceIDs: []string{"cisa-kev"}, Transport: upstream, Spacing: time.Nanosecond,
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}

	corpus, err := LoadCorpus(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	// Syncing the enrichment sources before the advisories is a reasonable thing
	// to do, and pruning here would throw the data away before what it belongs to
	// has been downloaded.
	if len(corpus.KEV) != 2 {
		t.Errorf("stored %d KEV entries, want the whole catalogue kept", len(corpus.KEV))
	}
}

func TestSyncRefusesAnUnknownSourceRatherThanSilentlyDoingNothing(t *testing.T) {
	_, err := Sync(context.Background(), SyncOptions{
		Dir: t.TempDir(), SourceIDs: []string{"not-a-source"}, Transport: newFakeUpstream(),
	})
	if err == nil {
		t.Fatal("an unknown source should be refused")
	}
	if !strings.Contains(err.Error(), "sync --list") {
		t.Errorf("the error should say how to find the real names, got %v", err)
	}
}

func TestFetcherReturnsTheCachedBodyWhenTheServerSays304(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.etag = `"v1"`
	upstream.serve("https://example.invalid/data.json", `{"hello": "world"}`)

	fetcher := testFetcher(t, upstream)
	first, cached, err := fetcher.Get(context.Background(), "https://example.invalid/data.json")
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if cached {
		t.Error("the first fetch cannot have come from a cache")
	}

	second, cached, err := fetcher.Get(context.Background(), "https://example.invalid/data.json")
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	// This is what makes a daily sync cost a handful of requests rather than a
	// full re-download of every advisory.
	if !cached {
		t.Error("the second fetch should have been answered from the cache")
	}
	if !bytes.Equal(first, second) {
		t.Error("the cached body differs from the original")
	}
	if stats := fetcher.Stats(); stats.NotModified != 1 {
		t.Errorf("not-modified count = %d", stats.NotModified)
	}
}

func TestFetcherServesFromTheCacheWhenOffline(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.serve("https://example.invalid/data.json", `{"hello": "world"}`)
	cacheDir := t.TempDir()

	online, err := NewFetcher(FetcherOptions{CacheDir: cacheDir, Transport: upstream, Spacing: time.Nanosecond})
	if err != nil {
		t.Fatalf("build fetcher: %v", err)
	}
	if _, _, err := online.Get(context.Background(), "https://example.invalid/data.json"); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}

	// The same command has to work on the air-gapped side against a corpus that
	// was downloaded on the connected side and carried in.
	offline, err := NewFetcher(FetcherOptions{CacheDir: cacheDir, Offline: true, Spacing: time.Nanosecond})
	if err != nil {
		t.Fatalf("build offline fetcher: %v", err)
	}
	body, cached, err := offline.Get(context.Background(), "https://example.invalid/data.json")
	if err != nil {
		t.Fatalf("offline get: %v", err)
	}
	if !cached || len(body) == 0 {
		t.Error("the offline fetcher should have served the cached copy")
	}

	if _, _, err := offline.Get(context.Background(), "https://example.invalid/other.json"); err == nil {
		t.Error("an offline fetch with nothing cached should fail rather than hang")
	}
}

func TestFetcherRefusesAnythingThatIsNotAnHTTPFetch(t *testing.T) {
	fetcher := testFetcher(t, newFakeUpstream())
	for _, rawURL := range []string{
		"file:///etc/passwd",
		"gopher://example.invalid/1",
		"https://",
		"data:text/plain,hello",
	} {
		// Source definitions can come from a configuration file, so this is a
		// real boundary rather than a formality.
		if _, _, err := fetcher.Get(context.Background(), rawURL); err == nil {
			t.Errorf("%q should have been refused", rawURL)
		}
	}
}

func TestFetcherRetriesAServerErrorAndGivesUpOnANotFound(t *testing.T) {
	upstream := newFakeUpstream()
	upstream.fail("https://example.invalid/flaky.json", http.StatusServiceUnavailable)
	upstream.fail("https://example.invalid/gone.json", http.StatusNotFound)

	fetcher, err := NewFetcher(FetcherOptions{
		CacheDir: t.TempDir(), Transport: upstream,
		Spacing: time.Nanosecond, RetryBackoff: time.Nanosecond, Retries: 2,
	})
	if err != nil {
		t.Fatalf("build fetcher: %v", err)
	}

	if _, _, err := fetcher.Get(context.Background(), "https://example.invalid/flaky.json"); err == nil {
		t.Fatal("expected the fetch to fail")
	}
	if got := upstream.count("https://example.invalid/flaky.json"); got != 3 {
		t.Errorf("a 503 was attempted %d times, want the initial call plus two retries", got)
	}

	if _, _, err := fetcher.Get(context.Background(), "https://example.invalid/gone.json"); err == nil {
		t.Fatal("expected the fetch to fail")
	}
	// A 404 will still be a 404 in two seconds, so retrying it only wastes the
	// upstream's time.
	if got := upstream.count("https://example.invalid/gone.json"); got != 1 {
		t.Errorf("a 404 was attempted %d times, want once", got)
	}
}

func TestDefaultSourcesAreOnlyTheOnesThatMayBeRedistributed(t *testing.T) {
	for _, id := range DefaultSourceIDs() {
		source, ok := SourceByID(id)
		if !ok {
			t.Fatalf("default source %q is not registered", id)
		}
		// A plain sync has to produce a corpus the project can publish as a
		// release artefact without anyone having to check terms first.
		if !source.Info().Redistributable {
			t.Errorf("source %q is on by default but is not redistributable", id)
		}
	}
}

func TestEverySourceDeclaresWhereItCameFromAndUnderWhatTerms(t *testing.T) {
	for _, source := range Sources() {
		info := source.Info()
		if info.Name == "" || info.Homepage == "" || info.License == "" || info.Summary == "" {
			t.Errorf("source %q is missing its description: %+v", info.ID, info)
		}
		if info.Kind != KindAdvisories && info.Kind != KindEnrichment {
			t.Errorf("source %q has kind %q", info.ID, info.Kind)
		}
	}
}
