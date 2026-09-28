package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/roccho-dev/envs/internal/appearance"
)

func main() {
	input := flag.String("input", "appearance/desired.jsonl", "appearance JSONL input")
	output := flag.String("output", "generated/appearance", "projection output directory")
	flag.Parse()
	if err := run(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(input, output string) error {
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	model, err := appearance.Load(file)
	if err != nil {
		return err
	}
	windowsTerminal, err := model.WindowsTerminal()
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"windows-terminal.appearance.json": append(windowsTerminal, '\n'),
		"vim-colors.vim":                  model.Vim(),
	}
	if yazi, enabled := model.Yazi(); enabled {
		files["yazi-theme.toml"] = yazi
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		path := filepath.Join(output, name)
		if err := writeAtomic(path, content); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".appearance-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}
