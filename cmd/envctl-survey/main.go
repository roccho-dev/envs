package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/roccho-dev/envs/internal/hostsurvey"
)

type osRunner struct{}

func (osRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func main() {
	host := flag.String("host", hostsurvey.CurrentHost(), "host identity")
	profilePath := flag.String("profile", "hosts/g6i3.profile.json", "host profile")
	requirementsPath := flag.String("requirements", "hosts/g6i3.desired.jsonl", "host requirement JSONL")
	surveyOutput := flag.String("survey-output", "", "optional survey output file")
	reconciliationOutput := flag.String("reconciliation-output", "", "optional reconciliation output file")
	flag.Parse()
	if err := run(*host, *profilePath, *requirementsPath, *surveyOutput, *reconciliationOutput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(host, profilePath, requirementsPath, surveyOutput, reconciliationOutput string) error {
	profileFile, err := os.Open(profilePath)
	if err != nil {
		return err
	}
	profile, err := hostsurvey.LoadProfile(profileFile)
	profileFile.Close()
	if err != nil {
		return err
	}
	requirementsFile, err := os.Open(requirementsPath)
	if err != nil {
		return err
	}
	requirements, err := hostsurvey.LoadRequirements(requirementsFile)
	requirementsFile.Close()
	if err != nil {
		return err
	}
	if err := hostsurvey.ValidateProfileRequirements(profile, requirements); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	survey, err := hostsurvey.Collect(ctx, osRunner{}, host, time.Now(), hostsurvey.Probes(requirements))
	if err != nil {
		return err
	}
	surveyBody, err := hostsurvey.Marshal(survey)
	if err != nil {
		return err
	}
	surveyBody = append(surveyBody, '\n')
	reconciliation, err := hostsurvey.Reconcile(profile, survey)
	if err != nil {
		return err
	}
	reconciliationBody, err := hostsurvey.MarshalReconciliation(reconciliation)
	if err != nil {
		return err
	}
	if surveyOutput == "" && reconciliationOutput == "" {
		_, _ = os.Stdout.Write(surveyBody)
		_, _ = os.Stdout.Write(reconciliationBody)
		return nil
	}
	if surveyOutput != "" {
		if err := os.WriteFile(surveyOutput, surveyBody, 0o600); err != nil {
			return err
		}
	}
	if reconciliationOutput != "" {
		if err := os.WriteFile(reconciliationOutput, reconciliationBody, 0o600); err != nil {
			return err
		}
	}
	return nil
}
