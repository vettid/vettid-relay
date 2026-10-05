package config

import (
	"slices"
	"strings"
	"testing"
)

const fpA = "31:A1:96:13:AA:10:F2:09:E0:89:45:F9:47:F9:4F:7C:E3:E6:E5:AC:34:24:57:FF:99:69:A6:79:86:92:8E:65"

func TestAndroidDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.AndroidPackage != "com.vettid.app" || len(c.AndroidCertFingerprints) != 3 || c.AndroidCertFingerprints[0] != fpA {
		t.Fatalf("%q %v", c.AndroidPackage, c.AndroidCertFingerprints)
	}
	if c.RateWebPerSec != 2 || c.RateWebBurst != 20 {
		t.Fatalf("web rate defaults %v/%d", c.RateWebPerSec, c.RateWebBurst)
	}
	// Defaults are copied, never shared with the package variable.
	c.AndroidCertFingerprints[0] = "x"
	if DefaultAndroidCertFingerprints[0] != fpA {
		t.Fatal("defaults aliased")
	}
}

func TestAndroidOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"RELAY_ANDROID_PACKAGE":     "org.example.app_2",
		"RELAY_ANDROID_CERT_SHA256": " 31a19613aa10f209e08945f947f94f7ce3e6e5ac342457ff9969a67986928e65 , , " + strings.ToLower(fpA),
		"RELAY_RATE_WEB_RPS":        "0.5",
		"RELAY_RATE_WEB_BURST":      "5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.AndroidPackage != "org.example.app_2" || !slices.Equal(c.AndroidCertFingerprints, []string{fpA}) || c.RateWebPerSec != 0.5 || c.RateWebBurst != 5 {
		t.Fatalf("%q %v", c.AndroidPackage, c.AndroidCertFingerprints)
	}
	// Set but empty: assetlinks.json is off.
	c, err = Load(env(map[string]string{"RELAY_ANDROID_CERT_SHA256": ""}))
	if err != nil || len(c.AndroidCertFingerprints) != 0 {
		t.Fatalf("%v %v", c.AndroidCertFingerprints, err)
	}
}

func TestAndroidRejects(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"short fp":       {"RELAY_ANDROID_CERT_SHA256": "31:A1"},
		"non-hex fp":     {"RELAY_ANDROID_CERT_SHA256": strings.Repeat("zz", 32)},
		"sha1 fp":        {"RELAY_ANDROID_CERT_SHA256": strings.Repeat("ab:", 19) + "ab"},
		"mixed colons":   {"RELAY_ANDROID_CERT_SHA256": "31A1:" + fpA[6:]},
		"bad package":    {"RELAY_ANDROID_PACKAGE": "vettid"},
		"package digit":  {"RELAY_ANDROID_PACKAGE": "com.1vettid.app"},
		"package space":  {"RELAY_ANDROID_PACKAGE": "com.vettid app"},
		"package empty":  {"RELAY_ANDROID_PACKAGE": ""},
		"web burst zero": {"RELAY_RATE_WEB_BURST": "0"},
		"web rps zero":   {"RELAY_RATE_WEB_RPS": "0"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// No fingerprints: the package is not needed.
	if _, err := Load(env(map[string]string{"RELAY_ANDROID_CERT_SHA256": "", "RELAY_ANDROID_PACKAGE": ""})); err != nil {
		t.Fatal(err)
	}
	var list []string
	for i := 0; i < 33; i++ {
		list = append(list, strings.Repeat("0", 62)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16]))
	}
	if _, err := ParseCertFingerprints(strings.Join(list, ",")); err == nil {
		t.Fatal("33 fingerprints accepted")
	}
}

func FuzzParseCertFingerprints(f *testing.F) {
	for _, s := range []string{fpA, strings.ToLower(fpA), strings.ReplaceAll(fpA, ":", ""), fpA + "," + fpA, "", ",", " , ", "31:A1", "::", strings.Repeat(":", 31)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		fps, err := ParseCertFingerprints(s)
		if err != nil {
			return
		}
		if len(fps) > maxCertFingerprints {
			t.Fatalf("%d fingerprints", len(fps))
		}
		seen := map[string]bool{}
		for _, fp := range fps {
			if len(fp) != 95 || seen[fp] {
				t.Fatalf("bad output %q", fp)
			}
			seen[fp] = true
			for i := 0; i < len(fp); i++ {
				ch := fp[i]
				if i%3 == 2 {
					if ch != ':' {
						t.Fatalf("bad output %q", fp)
					}
				} else if !(ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'F') {
					t.Fatalf("bad output %q", fp)
				}
			}
			// Canonical output parses to itself.
			again, err := ParseCertFingerprints(fp)
			if err != nil || len(again) != 1 || again[0] != fp {
				t.Fatalf("not idempotent: %q", fp)
			}
		}
	})
}
