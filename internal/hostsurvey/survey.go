package hostsurvey

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

const SurveyKind = "envs.hostSurvey.v1"

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Fact struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Survey struct {
	Kind         string `json:"kind"`
	Host         string `json:"host"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	ObservedAt   string `json:"observedAt"`
	Facts        []Fact `json:"facts"`
}

type Probe struct {
	ID      string
	Command string
	Args    []string
}

func DefaultProbes() []Probe {
	return []Probe{
		{ID: "capability.git", Command: "git", Args: []string{"--version"}},
		{ID: "capability.nix", Command: "nix", Args: []string{"--version"}},
		{ID: "capability.tailscale", Command: "tailscale", Args: []string{"version"}},
	}
}

func Collect(ctx context.Context, runner Runner, host string, now time.Time, probes []Probe) (Survey, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return Survey{}, fmt.Errorf("host is required")
	}
	if host != "g6i3" {
		return Survey{}, fmt.Errorf("survey host %q is outside Issue #10", host)
	}
	facts := make([]Fact, 0, len(probes))
	seen := map[string]bool{}
	for _, probe := range probes {
		if probe.ID == "" || probe.Command == "" {
			return Survey{}, fmt.Errorf("probe id and command are required")
		}
		if seen[probe.ID] {
			return Survey{}, fmt.Errorf("duplicate probe %q", probe.ID)
		}
		seen[probe.ID] = true
		output, err := runner.Run(ctx, probe.Command, probe.Args...)
		fact := Fact{ID: probe.ID}
		if err != nil {
			fact.Status = "missing"
			fact.Detail = err.Error()
		} else {
			fact.Status = "present"
			fact.Value = strings.TrimSpace(string(output))
		}
		facts = append(facts, fact)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	return Survey{
		Kind:         SurveyKind,
		Host:         host,
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		ObservedAt:   now.UTC().Format(time.RFC3339),
		Facts:        facts,
	}, nil
}

func Marshal(s Survey) ([]byte, error) {
	if s.Kind != SurveyKind || s.Host != "g6i3" || s.Platform == "" || s.Architecture == "" || s.ObservedAt == "" {
		return nil, fmt.Errorf("incomplete survey")
	}
	return json.MarshalIndent(s, "", "  ")
}

func CurrentHost() string {
	host, _ := os.Hostname()
	return strings.ToLower(host)
}
