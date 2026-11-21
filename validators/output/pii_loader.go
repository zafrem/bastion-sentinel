package output

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/zafrem/bastion-sentinel/config"
	"gopkg.in/yaml.v3"
)

// PIIExternalPattern represents the YAML format used by pii-pattern-engine.
type PIIExternalPattern struct {
	ID          string `yaml:"id"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Policy      struct {
		ActionOnMatch string `yaml:"action_on_match"`
		Severity      string `yaml:"severity"`
	} `yaml:"policy"`
}

type PIIExternalConfig struct {
	PIIConfig struct {
		Enabled  bool                 `yaml:"enabled"`
		Patterns []PIIExternalPattern `yaml:"patterns"`
	} `yaml:"pii_config"`
}

// LoadExternalPatterns reads pii-pattern-engine style YAML files from a directory
// and converts them into our internal PIIPatternConfig.
func LoadExternalPatterns(dir string) ([]config.PIIPatternConfig, error) {
	var patterns []config.PIIPatternConfig

	// If dir is relative, attempt to resolve it from the module or workspace root.
	if !filepath.IsAbs(dir) {
		cwd, err := os.Getwd()
		if err == nil {
			for cwd != "/" {
				if _, err := os.Stat(filepath.Join(cwd, "go.mod")); err == nil {
					if fi, err := os.Stat(filepath.Join(cwd, dir)); err == nil && fi.IsDir() {
						dir = filepath.Join(cwd, dir)
						break
					}
					if fi, err := os.Stat(filepath.Join(cwd, "sentinel", dir)); err == nil && fi.IsDir() {
						dir = filepath.Join(cwd, "sentinel", dir)
						break
					}
				}
				cwd = filepath.Dir(cwd)
			}
		}
	}

	// Read through an os.Root so a symlink inside the directory cannot point the loader at a file outside
	// it, and the directory cannot be swapped for another between the walk and the read (CWE-367).
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open pattern directory %s: %w", dir, err)
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := fs.ReadFile(rootFS, path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filepath.Join(dir, path), err)
		}

		var extCfg PIIExternalConfig
		if err := yaml.Unmarshal(data, &extCfg); err != nil {
			var justPatterns struct {
				Patterns []PIIExternalPattern `yaml:"patterns"`
			}
			if err2 := yaml.Unmarshal(data, &justPatterns); err2 == nil && len(justPatterns.Patterns) > 0 {
				for i, p := range justPatterns.Patterns {
					patterns = append(patterns, convertPattern(p, fmt.Sprintf("%s-%d", filepath.Base(path), i)))
				}
				return nil
			}
			var flatPatterns []PIIExternalPattern
			if err3 := yaml.Unmarshal(data, &flatPatterns); err3 == nil {
				for i, p := range flatPatterns {
					patterns = append(patterns, convertPattern(p, fmt.Sprintf("%s-%d", filepath.Base(path), i)))
				}
				return nil
			}
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		for i, p := range extCfg.PIIConfig.Patterns {
			patterns = append(patterns, convertPattern(p, fmt.Sprintf("%s-%d", filepath.Base(path), i)))
		}

		// some files might just have 'patterns:' at the root level without pii_config
		if len(extCfg.PIIConfig.Patterns) == 0 {
			var rootPatterns struct {
				Patterns []PIIExternalPattern `yaml:"patterns"`
			}
			if err := yaml.Unmarshal(data, &rootPatterns); err == nil {
				for i, p := range rootPatterns.Patterns {
					patterns = append(patterns, convertPattern(p, fmt.Sprintf("%s-%d", filepath.Base(path), i)))
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return patterns, nil
}

func convertPattern(p PIIExternalPattern, fallbackID string) config.PIIPatternConfig {
	severity := p.Policy.Severity
	if severity == "" {
		severity = "high"
	}
	id := p.ID
	if id == "" {
		id = fallbackID
	}
	name := p.Description
	if name == "" {
		name = id
	}
	return config.PIIPatternConfig{
		ID:       id,
		Name:     name,
		Pattern:  p.Pattern,
		Severity: severity,
		Action:   p.Policy.ActionOnMatch,
	}
}
