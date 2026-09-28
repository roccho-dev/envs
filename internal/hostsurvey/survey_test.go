package hostsurvey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	values map[string]string
}

func (f fakeRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	value, ok := f.values[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return []byte(value), nil
}

func TestCollectIsSortedAndReadOnly(t *testing.T) {
	probes := []Probe{
		{ID: "capability.tailscale", Command: "tailscale"},
		{ID: "capability.git", Command: "git"},
		{ID: "capability.nix", Command: "nix"},
	}
	now := time.Date(2026, 7, 12, 7, 0, 0, 0, time.UTC)
	survey, err := Collect(context.Background(), fakeRunner{values: map[string]string{
		"git": "git version 2.54.0\n",
		"nix": "nix (Nix) 2.31.2\n",
	}}, "G6I3", now, probes)
	if err != nil {
		t.Fatal(err)
	}
	if survey.Host != "g6i3" || survey.Kind != SurveyKind {
		t.Fatalf("unexpected survey identity: %#v", survey)
	}
	if len(survey.Facts) != 3 {
		t.Fatalf("facts = %d", len(survey.Facts))
	}
	if survey.Facts[0].ID != "capability.git" || survey.Facts[1].ID != "capability.nix" || survey.Facts[2].ID != "capability.tailscale" {
		t.Fatalf("facts are not stable: %#v", survey.Facts)
	}
	if survey.Facts[2].Status != "missing" {
		t.Fatalf("missing capability was not observed: %#v", survey.Facts[2])
	}
	body, err := Marshal(survey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "apply") || strings.Contains(string(body), "install") {
		t.Fatal("read-only survey emitted mutation meaning")
	}
}

func TestCollectRejectsScopeAndDuplicateProbes(t *testing.T) {
	if _, err := Collect(context.Background(), fakeRunner{}, "other", time.Now(), nil); err == nil {
		t.Fatal("expected host scope rejection")
	}
	_, err := Collect(context.Background(), fakeRunner{}, "g6i3", time.Now(), []Probe{
		{ID: "same", Command: "one"},
		{ID: "same", Command: "two"},
	})
	if err == nil {
		t.Fatal("expected duplicate probe rejection")
	}
}
