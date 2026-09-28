package hostsurvey

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var requirementIDPattern = regexp.MustCompile(`^capability\.[a-z0-9][a-z0-9._-]*$`)

type Requirement struct {
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

func LoadRequirements(r io.Reader) ([]Requirement, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := map[string]bool{}
	var requirements []Requirement
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var requirement Requirement
		if err := decoder.Decode(&requirement); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if requirement.Kind != "envs.hostRequirement.v1" {
			return nil, fmt.Errorf("line %d: unsupported kind %q", line, requirement.Kind)
		}
		if !requirementIDPattern.MatchString(requirement.ID) {
			return nil, fmt.Errorf("line %d: invalid requirement id %q", line, requirement.ID)
		}
		if seen[requirement.ID] {
			return nil, fmt.Errorf("line %d: duplicate requirement %q", line, requirement.ID)
		}
		seen[requirement.ID] = true
		if strings.TrimSpace(requirement.Command) == "" || strings.ContainsAny(requirement.Command, `/\\`) {
			return nil, fmt.Errorf("line %d: command must be one executable name", line)
		}
		for _, arg := range requirement.Args {
			if strings.ContainsAny(arg, "\r\n\x00") {
				return nil, fmt.Errorf("line %d: invalid command argument", line)
			}
		}
		requirements = append(requirements, requirement)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(requirements) == 0 {
		return nil, fmt.Errorf("no host requirements declared")
	}
	sort.Slice(requirements, func(i, j int) bool { return requirements[i].ID < requirements[j].ID })
	return requirements, nil
}

func Probes(requirements []Requirement) []Probe {
	probes := make([]Probe, 0, len(requirements))
	for _, requirement := range requirements {
		probes = append(probes, Probe{ID: requirement.ID, Command: requirement.Command, Args: append([]string(nil), requirement.Args...)})
	}
	return probes
}

func ValidateProfileRequirements(profile Profile, requirements []Requirement) error {
	declared := map[string]bool{}
	for _, requirement := range requirements {
		declared[requirement.ID] = true
	}
	if len(declared) != len(profile.RequiredSurveyFacts) {
		return fmt.Errorf("profile and requirement counts differ")
	}
	for _, required := range profile.RequiredSurveyFacts {
		if !declared[required] {
			return fmt.Errorf("profile fact %q has no requirement", required)
		}
	}
	return nil
}
