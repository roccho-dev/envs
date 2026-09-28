package hostsurvey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

type Authority struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
	Projection string `json:"projection"`
}

type Bootstrap struct {
	Transport    string `json:"transport"`
	SSOTEndpoint string `json:"ssotEndpoint"`
}

type Profile struct {
	Kind                string    `json:"kind"`
	ID                  string    `json:"id"`
	Platform            string    `json:"platform"`
	Architecture        string    `json:"architecture"`
	Authority           Authority `json:"authority"`
	Bootstrap           Bootstrap `json:"bootstrap"`
	RequiredSurveyFacts []string  `json:"requiredSurveyFacts"`
	MutationPolicy      string    `json:"mutationPolicy"`
}

type Reconciliation struct {
	Kind         string   `json:"kind"`
	Host         string   `json:"host"`
	Status       string   `json:"status"`
	MissingFacts []string `json:"missingFacts,omitempty"`
}

func LoadProfile(r io.Reader) (Profile, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, err
	}
	if profile.Kind != "envs.hostProfile.v1" || profile.ID != "g6i3" {
		return Profile{}, fmt.Errorf("profile must be envs.hostProfile.v1 for g6i3")
	}
	if profile.Platform != "linux" || profile.Architecture != "amd64" {
		return Profile{}, fmt.Errorf("g6i3 profile must target linux/amd64")
	}
	if profile.Authority.Repository != "roccho-dev/envs" || profile.Authority.Ref != "proposals" || profile.Authority.Projection != "hosts/g6i3.desired.jsonl" {
		return Profile{}, fmt.Errorf("g6i3 authority must be the proposals projection in envs")
	}
	if profile.Bootstrap.Transport != "tailnet" || profile.Bootstrap.SSOTEndpoint != "http://nixos-vm:46121/v1/hosts/g6i3" {
		return Profile{}, fmt.Errorf("g6i3 bootstrap must use the canonical tailnet SSOT endpoint")
	}
	if profile.MutationPolicy != "read-only-survey-until-profile-accepted" {
		return Profile{}, fmt.Errorf("unexpected mutation policy")
	}
	seen := map[string]bool{}
	for _, fact := range profile.RequiredSurveyFacts {
		if fact == "" || seen[fact] {
			return Profile{}, fmt.Errorf("required survey facts must be non-empty and unique")
		}
		seen[fact] = true
	}
	if len(profile.RequiredSurveyFacts) == 0 {
		return Profile{}, fmt.Errorf("required survey facts are empty")
	}
	return profile, nil
}

func Reconcile(profile Profile, survey Survey) (Reconciliation, error) {
	if profile.ID != survey.Host {
		return Reconciliation{}, fmt.Errorf("survey host %q does not match profile %q", survey.Host, profile.ID)
	}
	if profile.Platform != survey.Platform || profile.Architecture != survey.Architecture {
		return Reconciliation{}, fmt.Errorf("survey target %s/%s does not match profile %s/%s", survey.Platform, survey.Architecture, profile.Platform, profile.Architecture)
	}
	present := map[string]bool{}
	for _, fact := range survey.Facts {
		if fact.Status == "present" {
			present[fact.ID] = true
		}
	}
	var missing []string
	for _, required := range profile.RequiredSurveyFacts {
		if !present[required] {
			missing = append(missing, required)
		}
	}
	sort.Strings(missing)
	result := Reconciliation{Kind: "envs.hostReconciliation.v1", Host: profile.ID, MissingFacts: missing}
	if len(missing) == 0 {
		result.Status = "survey-converged"
	} else {
		result.Status = "profile-required"
	}
	return result, nil
}

func MarshalReconciliation(r Reconciliation) ([]byte, error) {
	if r.Kind != "envs.hostReconciliation.v1" || r.Host != "g6i3" || (r.Status != "survey-converged" && r.Status != "profile-required") {
		return nil, fmt.Errorf("invalid reconciliation")
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(bytes.TrimSpace(body), '\n'), nil
}
