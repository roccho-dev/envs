package appearance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const ProjectionVersion = "envs.appearanceProjection.v1"

var colorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

type Palette struct {
	Kind   string            `json:"kind"`
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Colors map[string]string `json:"colors"`
}

type Roles struct {
	Kind    string            `json:"kind"`
	ID      string            `json:"id"`
	Palette string            `json:"palette"`
	Roles   map[string]string `json:"roles"`
}

type Font struct {
	Kind   string  `json:"kind"`
	ID     string  `json:"id"`
	Family string  `json:"family"`
	Size   float64 `json:"size"`
}

type Target struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Target  string `json:"target"`
	Enabled bool   `json:"enabled"`
}

type Model struct {
	Palette Palette
	Roles   Roles
	Font    Font
	Targets map[string]Target
}

type recordHeader struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func Load(r io.Reader) (Model, error) {
	var model Model
	model.Targets = map[string]Target{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var header recordHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			return Model{}, fmt.Errorf("line %d: %w", line, err)
		}
		if header.Kind == "" || header.ID == "" {
			return Model{}, fmt.Errorf("line %d: kind and id are required", line)
		}
		identity := header.Kind + ":" + header.ID
		if seen[identity] {
			return Model{}, fmt.Errorf("line %d: duplicate record %s", line, identity)
		}
		seen[identity] = true
		switch header.Kind {
		case "envs.appearance.palette.v1":
			if model.Palette.ID != "" {
				return Model{}, errors.New("exactly one palette is supported")
			}
			if err := strictUnmarshal(raw, &model.Palette); err != nil {
				return Model{}, fmt.Errorf("line %d: %w", line, err)
			}
		case "envs.appearance.roles.v1":
			if model.Roles.ID != "" {
				return Model{}, errors.New("exactly one role set is supported")
			}
			if err := strictUnmarshal(raw, &model.Roles); err != nil {
				return Model{}, fmt.Errorf("line %d: %w", line, err)
			}
		case "envs.appearance.font.v1":
			if model.Font.ID != "" {
				return Model{}, errors.New("exactly one font preference is supported")
			}
			if err := strictUnmarshal(raw, &model.Font); err != nil {
				return Model{}, fmt.Errorf("line %d: %w", line, err)
			}
		case "envs.appearance.target.v1":
			var target Target
			if err := strictUnmarshal(raw, &target); err != nil {
				return Model{}, fmt.Errorf("line %d: %w", line, err)
			}
			if _, ok := model.Targets[target.Target]; ok {
				return Model{}, fmt.Errorf("line %d: duplicate target %q", line, target.Target)
			}
			model.Targets[target.Target] = target
		default:
			return Model{}, fmt.Errorf("line %d: unsupported kind %q", line, header.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		return Model{}, err
	}
	if err := validate(model); err != nil {
		return Model{}, err
	}
	return model, nil
}

func strictUnmarshal(raw []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func validate(model Model) error {
	if model.Palette.ID == "" || model.Palette.Name == "" || len(model.Palette.Colors) == 0 {
		return errors.New("palette is required")
	}
	for name, value := range model.Palette.Colors {
		if !colorPattern.MatchString(value) {
			return fmt.Errorf("palette color %q is invalid", name)
		}
	}
	if model.Roles.ID == "" || model.Roles.Palette != model.Palette.ID {
		return errors.New("roles must reference the selected palette")
	}
	required := []string{"background", "foreground", "surface", "selection", "primary", "diagnostic", "warning", "error"}
	for _, role := range required {
		colorName, ok := model.Roles.Roles[role]
		if !ok {
			return fmt.Errorf("required role %q is missing", role)
		}
		if _, ok := model.Palette.Colors[colorName]; !ok {
			return fmt.Errorf("role %q references unknown color %q", role, colorName)
		}
	}
	if model.Font.ID == "" || strings.TrimSpace(model.Font.Family) == "" || model.Font.Size <= 0 {
		return errors.New("font preference is required")
	}
	for _, target := range []string{"windows-terminal", "vim"} {
		if item, ok := model.Targets[target]; !ok || !item.Enabled {
			return fmt.Errorf("required target %q is not enabled", target)
		}
	}
	for name := range model.Targets {
		switch name {
		case "windows-terminal", "vim", "yazi":
		default:
			return fmt.Errorf("unsupported target %q", name)
		}
	}
	return nil
}

func (m Model) color(role string) string {
	return strings.ToUpper(m.Palette.Colors[m.Roles.Roles[role]])
}

func (m Model) WindowsTerminal() ([]byte, error) {
	projection := map[string]any{
		"kind":   ProjectionVersion,
		"target": "windows-terminal",
		"profiles": map[string]any{
			"defaults": map[string]any{
				"colorScheme": m.Palette.Name,
				"font": map[string]any{"face": m.Font.Family, "size": m.Font.Size},
			},
		},
		"schemes": []any{map[string]any{
			"name":       m.Palette.Name,
			"background": m.color("background"),
			"foreground": m.color("foreground"),
			"selectionBackground": m.color("selection"),
			"black":      m.color("background"),
			"white":      m.color("foreground"),
			"brightBlue": m.color("primary"),
			"brightCyan": m.color("diagnostic"),
			"brightYellow": m.color("warning"),
			"brightRed":  m.color("error"),
		}},
	}
	return json.MarshalIndent(projection, "", "  ")
}

func (m Model) Vim() []byte {
	lines := []string{
		"\" generated from envs appearance JSONL; do not edit",
		"set termguicolors",
		"highlight Normal guifg=" + m.color("foreground") + " guibg=" + m.color("background"),
		"highlight Pmenu guifg=" + m.color("foreground") + " guibg=" + m.color("surface"),
		"highlight PmenuSel guifg=" + m.color("background") + " guibg=" + m.color("primary"),
		"highlight DiagnosticInfo guifg=" + m.color("diagnostic"),
		"highlight DiagnosticWarn guifg=" + m.color("warning"),
		"highlight DiagnosticError guifg=" + m.color("error"),
		"highlight WarningMsg guifg=" + m.color("warning"),
		"highlight ErrorMsg guifg=" + m.color("error"),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func (m Model) Yazi() ([]byte, bool) {
	target, ok := m.Targets["yazi"]
	if !ok || !target.Enabled {
		return nil, false
	}
	pairs := map[string]string{
		"background": m.color("background"),
		"foreground": m.color("foreground"),
		"selection":  m.color("selection"),
		"accent":     m.color("primary"),
		"warning":    m.color("warning"),
		"error":      m.color("error"),
	}
	keys := make([]string, 0, len(pairs))
	for key := range pairs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString("# generated from envs appearance JSONL; do not edit\n[appearance]\n")
	for _, key := range keys {
		fmt.Fprintf(&out, "%s = %q\n", key, pairs[key])
	}
	return []byte(out.String()), true
}
