package hostsurvey

import (
	"strings"
	"testing"
)

const validProfile = `{
  "kind":"envs.hostProfile.v1",
  "id":"g6i3",
  "platform":"linux",
  "architecture":"amd64",
  "authority":{"repository":"roccho-dev/envs","ref":"proposals","projection":"hosts/g6i3.desired.jsonl"},
  "bootstrap":{"transport":"tailnet","ssotEndpoint":"http://nixos-vm:46121/v1/hosts/g6i3"},
  "requiredSurveyFacts":["capability.git","capability.nix","capability.tailscale"],
  "mutationPolicy":"read-only-survey-until-profile-accepted"
}`

func TestProfileAndSurveyReconcileDeterministically(t *testing.T) {
	profile, err := LoadProfile(strings.NewReader(validProfile))
	if err != nil {
		t.Fatal(err)
	}
	survey := Survey{
		Kind: SurveyKind, Host: "g6i3", Platform: "linux", Architecture: "amd64", ObservedAt: "2026-07-12T07:00:00Z",
		Facts: []Fact{
			{ID: "capability.tailscale", Status: "missing"},
			{ID: "capability.git", Status: "present", Value: "git version 2.54.0"},
			{ID: "capability.nix", Status: "present", Value: "nix 2.31.2"},
		},
	}
	result, err := Reconcile(profile, survey)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "profile-required" || len(result.MissingFacts) != 1 || result.MissingFacts[0] != "capability.tailscale" {
		t.Fatalf("unexpected reconciliation: %#v", result)
	}
	body, err := MarshalReconciliation(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "capability.tailscale") {
		t.Fatalf("missing fact not retained: %s", body)
	}

	survey.Facts[0].Status = "present"
	result, err = Reconcile(profile, survey)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "survey-converged" || len(result.MissingFacts) != 0 {
		t.Fatalf("unexpected converged result: %#v", result)
	}
}

func TestProfileFailsClosed(t *testing.T) {
	for _, replacement := range []string{
		`"id":"other"`,
		`"platform":"windows"`,
		`"ref":"main"`,
		`"transport":"github"`,
		`"mutationPolicy":"apply"`,
	} {
		input := validProfile
		switch replacement {
		case `"id":"other"`:
			input = strings.Replace(input, `"id":"g6i3"`, replacement, 1)
		case `"platform":"windows"`:
			input = strings.Replace(input, `"platform":"linux"`, replacement, 1)
		case `"ref":"main"`:
			input = strings.Replace(input, `"ref":"proposals"`, replacement, 1)
		case `"transport":"github"`:
			input = strings.Replace(input, `"transport":"tailnet"`, replacement, 1)
		case `"mutationPolicy":"apply"`:
			input = strings.Replace(input, `"mutationPolicy":"read-only-survey-until-profile-accepted"`, replacement, 1)
		}
		if _, err := LoadProfile(strings.NewReader(input)); err == nil {
			t.Fatalf("expected failure for %s", replacement)
		}
	}
}
