package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Configはsisakulintの設定を表す構造体でのインスタンスは".github"に位置する"sisakulint.yml"を読み込んでparse
type Config struct {
	//selfhostedrunner : setting for self-hosted runner
	SelfHostedRunner struct {
		//Labelsはself-hosted runnerのラベル
		Labels []string `yaml:"labels"`
	} `yaml:"self-hosted-runner"`
	// ConfigVariablesはチェックされるworkflowで使用される設定変数の名前を示す
	//この値がnilの時にvarsのコンテキストのプロパティ名はチェックされない
	ConfigVariables []string `yaml:"config-variables"`
}

// parseConfigは与えられたbyte sliceをConfigにparseする
func parseConfig(b []byte, path string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse config file %q: %s", path, msg)
	}
	return &c, nil
}

// ReadConfigFileは指定されたファイルパスからsisakulint.yamlを読み込む
func ReadConfigFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	return parseConfig(b, path)
}

// loadRepoConfigは、リポジトリ.github/sisakulint.yml or .github/sisakulint.ymlを読み込む
func loadRepoConfig(root string) (*Config, error) {
	for _, f := range []string{"sisakulint.yaml", "sisakulint.yml"} {
		path := filepath.Join(root, ".github", f)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cfg, err := parseConfig(b, path)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	return nil, nil
}

// writeDefaultConfigFileは指定されたファイルパスにデフォルトの設定ファイルを書き込む
func writeDefaultConfigFile(path string) error {
	b := []byte(`
	# Configuration file for sisakulint
# Use this file to customize the behavior of sisakulint
# self-hosted-runner section is for configuring self-hosted runners.
self-hosted-runner:
  # Use the labels key to specify labels for self-hosted runners used in your project as an array of strings.
  # This allows sisakulint to verify that these labels are correctly configured.
  # 🧠 Example: labels: ["linux-large", "windows-2xlarge"]
  # Note: Ensure that the labels match those configured in your self-hosted runner settings.
  labels: []

# config-variables section is for specifying configuration variables defined in your repository or organization.
# Setting it to null disables the check for configuration variables.
# An empty array means no configuration variable is allowed.
# 🧠 Example: config-variables: ["CI_ENVIRONMENT", "DEPLOY_TARGET"]
# Note: List all the configuration variables that are used in your GitHub Actions workflows.
config-variables: null

# Add other optional settings below.
# 🧠 Example: some-option: value
# Note: Refer to the sisakulint documentation for more information on available settings.
	`)
	if err := os.WriteFile(path, b, 0644); err != nil {
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}
	return nil
}
