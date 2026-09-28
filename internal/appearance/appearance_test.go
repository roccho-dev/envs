package appearance

import (
	"bytes"
	"strings"
	"testing"
)

const validRecords = `{"kind":"envs.appearance.palette.v1","id":"catppuccin-mocha","name":"Catppuccin Mocha","colors":{"background":"#1E1E2E","foreground":"#CDD6F4","surface":"#313244","selection":"#45475A","primary":"#89B4FA","diagnostic":"#89DCEB","warning":"#F9E2AF","error":"#F38BA8"}}
{"kind":"envs.appearance.roles.v1","id":"default","palette":"catppuccin-mocha","roles":{"background":"background","foreground":"foreground","surface":"surface","selection":"selection","primary":"primary","diagnostic":"diagnostic","warning":"warning","error":"error"}}
{"kind":"envs.appearance.font.v1","id":"font","family":"HackGen35 Console NF","size":9}
{"kind":"envs.appearance.target.v1","id":"wt","target":"windows-terminal","enabled":true}
{"kind":"envs.appearance.target.v1","id":"vim","target":"vim","enabled":true}
{"kind":"envs.appearance.target.v1","id":"yazi","target":"yazi","enabled":true}
`

func TestProjectionsAreDeterministicAndAppearanceOnly(t *testing.T) {
	model, err := Load(strings.NewReader(validRecords))
	if err != nil {
		t.Fatal(err)
	}
	first, err := model.WindowsTerminal()
	if err != nil {
		t.Fatal(err)
	}
	second, err := model.WindowsTerminal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("Windows Terminal projection is not deterministic")
	}
	text := string(first)
	for _, forbidden := range []string{"commandline", "startingDirectory", "guid", "source", "launcher", "herdr"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("functional field %q leaked into appearance projection", forbidden)
		}
	}
	for _, required := range []string{"Catppuccin Mocha", "HackGen35 Console NF", "#1E1E2E", "#CDD6F4"} {
		if !strings.Contains(text, required) {
			t.Fatalf("projection missing %q", required)
		}
	}
	vim := string(model.Vim())
	for _, required := range []string{"set termguicolors", "highlight Normal", "highlight PmenuSel", "highlight DiagnosticError"} {
		if !strings.Contains(vim, required) {
			t.Fatalf("Vim projection missing %q", required)
		}
	}
	if strings.Contains(vim, "ctermbg=13") {
		t.Fatal("Vim projection retained the ANSI pink fallback")
	}
	yazi, enabled := model.Yazi()
	if !enabled || !strings.Contains(string(yazi), "[appearance]") {
		t.Fatal("declared Yazi projection is missing")
	}
}

func TestYaziIsOmittedWithoutDeclaredConsumer(t *testing.T) {
	withoutYazi := strings.ReplaceAll(validRecords, `{"kind":"envs.appearance.target.v1","id":"yazi","target":"yazi","enabled":true}
`, "")
	model, err := Load(strings.NewReader(withoutYazi))
	if err != nil {
		t.Fatal(err)
	}
	if _, enabled := model.Yazi(); enabled {
		t.Fatal("Yazi projection was generated without a declared consumer")
	}
}

func TestInvalidAndAmbiguousRecordsFailClosed(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"invalid color", strings.Replace(validRecords, "#1E1E2E", "pink", 1)},
		{"unknown field", strings.Replace(validRecords, `"name":"Catppuccin Mocha"`, `"name":"Catppuccin Mocha","commandline":"bad"`, 1)},
		{"duplicate identity", validRecords + `{"kind":"envs.appearance.target.v1","id":"vim","target":"vim","enabled":true}` + "\n"},
		{"missing required role", strings.Replace(validRecords, `"error":"error"`, `"removed":"error"`, 1)},
		{"unknown target", validRecords + `{"kind":"envs.appearance.target.v1","id":"other","target":"other","enabled":true}` + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(tt.data)); err == nil {
				t.Fatal("expected fail-closed validation")
			}
		})
	}
}
