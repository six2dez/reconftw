// cloud_enum_test.go — CloudEnumTask + MisconfigTask parser assertions (OSINT-07 / D-O10).
//
// These verify the security-severity classification of exposed cloud buckets and
// third-party misconfigurations, and the per-provider (S3/GCP/Azure) tagging.
package osint

import "testing"

func TestParseCloudEnumLines_ProviderClassification(t *testing.T) {
	lines := []string{
		"reconFTW cloud_enum banner — scanning",        // noise, dropped
		"[+] OPEN S3 BUCKET: http://acme.s3.amazonaws.com/", // s3, public → high
		"[*] Protected S3 Bucket: acme-private.s3.amazonaws.com",
		"Google Storage Bucket: storage.googleapis.com/acme",  // gcp
		"[+] PUBLIC Azure Blob Container: acme.blob.core.windows.net", // azure, public → high
	}
	recs := parseCloudEnumLines(lines)
	if len(recs) != 4 {
		t.Fatalf("expected 4 bucket records, got %d: %+v", len(recs), recs)
	}

	byCat := map[string]OSINTFindingRecord{}
	for _, r := range recs {
		if r.Source != "cloud_enum" || r.Class != "osint" {
			t.Errorf("unexpected source/class: %+v", r)
		}
		byCat[r.Category] = r
	}
	for _, want := range []string{"cloud-bucket-s3", "cloud-bucket-gcp", "cloud-bucket-azure"} {
		if _, ok := byCat[want]; !ok {
			t.Errorf("missing provider category %q", want)
		}
	}
	// Public/open buckets must be high severity (exploitable exposure).
	if got := byCat["cloud-bucket-azure"].Severity; got != "high" {
		t.Errorf("public azure bucket should be high, got %q", got)
	}
}

func TestParseCloudEnumLines_EmptyAndNoise(t *testing.T) {
	if recs := parseCloudEnumLines(nil); recs != nil {
		t.Fatalf("expected nil for nil input, got %v", recs)
	}
	if recs := parseCloudEnumLines([]string{"just a progress line", "[..] 50%"}); recs != nil {
		t.Fatalf("expected nil for noise-only input, got %v", recs)
	}
}

func TestLabelOf(t *testing.T) {
	if got := labelOf("example.com"); got != "example" {
		t.Errorf("labelOf(example.com)=%q want example", got)
	}
	if got := labelOf("nodot"); got != "nodot" {
		t.Errorf("labelOf(nodot)=%q want nodot", got)
	}
}

func TestParseMisconfigLines_Severity(t *testing.T) {
	lines := []string{
		"misconfig-mapper banner v1.0",                                  // noise, dropped
		"[+] Detected exposed Jira board: https://acme.atlassian.net",   // hit → medium/high
		"[+] EXPLOITABLE: public Trello board https://trello.com/acme",  // exploitable → high
		"checked 42 services",                                           // noise, dropped
	}
	recs := parseMisconfigLines(lines)
	if len(recs) != 2 {
		t.Fatalf("expected 2 misconfig records, got %d: %+v", len(recs), recs)
	}
	var sawHigh bool
	for _, r := range recs {
		if r.Source != "third_party_misconfig" || r.Category != "misconfig" {
			t.Errorf("unexpected source/category: %+v", r)
		}
		if r.Severity == "high" {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("expected at least one high-severity (exploitable) misconfig")
	}
}
