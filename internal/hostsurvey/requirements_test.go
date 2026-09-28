package hostsurvey

import (
	"strings"
	"testing"
)

const validRequirements = `{"kind":"envs.hostRequirement.v1","id":"capability.git","command":"git","args":["--version"]}
{"kind":"envs.hostRequirement.v1","id":"capability.nix","command":"nix","args":["--version"]}
{"kind":"envs.hostRequirement.v1","id":"capability.tailscale","command":"tailscale","args":["version"]}
`

func TestRequirementsProduceStableProbesAndMatchProfile(t *testing.T) {
	requirements, err := LoadRequirements(strings.NewReader(validRequirements))
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 3 || requirements[0].ID != "capability.git" || requirements[2].ID != "capability.tailscale" {
		t.Fatalf("unstable requirements: %#v", requirements)
	}
	profile, err := LoadProfile(strings.NewReader(validProfile))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfileRequirements(profile, requirements); err != nil {
		t.Fatal(err)
	}
	probes := Probes(requirements)
	if probes[0].Command != "git" || len(probes[0].Args) != 1 || probes[0].Args[0] != "--version" {
		t.Fatalf("unexpected probe: %#v", probes[0])
	}
}

func TestRequirementsFailClosed(t *testing.T) {
	cases := []string{
		strings.Replace(validRequirements, "envs.hostRequirement.v1", "other", 1),
		validRequirements + `{"kind":"envs.hostRequirement.v1","id":"capability.git","command":"git"}` + "\n",
		strings.Replace(validRequirements, `"command":"git"`, `"command":"/usr/bin/git"`, 1),
		strings.Replace(validRequirements, `"args":["--version"]`, `"args":["bad\narg"]`, 1),
		"",
	}
	for i, input := range cases {
		if _, err := LoadRequirements(strings.NewReader(input)); err == nil {
			t.Fatalf("case %d: expected fail-closed validation", i)
		}
	}
}
