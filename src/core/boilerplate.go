package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Boilerはsisakulintの設定を表す構造体でのインスタンスは".github"に位置する"boilerplate.yml"を読み込んでparse
type Boiler struct {
	//selfhostedrunner : setting for self-hosted runner
	SelfHostedRunner struct {
		//Labelsはself-hosted runnerのラベル
		Labels []string `yaml:"labels"`
	} `yaml:"self-hosted-runner"`
	// ConfigVariablesはチェックされるworkflowで使用される設定変数の名前を示す
	//この値がnilの時にvarsのコンテキストのプロパティ名はチェックされない
	ConfigVariables []string `yaml:"config-variables"`
}

//parseBoilerは与えられたbyte sliceをConfigにparseする
func parseBoiler(b []byte, path string) (*Boiler, error) {
	var c Boiler
	if err := yaml.Unmarshal(b, &c); err != nil {
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse boilerplate file %q: %s", path, msg)
	}
	return &c, nil
}

// ReadBoilerは指定されたファイルパスからboilerplate.yamlを読み込む
func ReadBoiler(path string) (*Boiler, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read boilerplate file %q: %w", path, err)
	}
	return parseBoiler(b, path)
}

//loadBoilerは.github/boilerplate.yml or .github/boilerplate.ymlを読み込む
func loadBoiler(root string) (*Boiler, error) {
	for _, f := range []string{"boilerplate.yaml", "boilerplate.yml"} {
		path := filepath.Join(root, ".github", f)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cfg, err := parseBoiler(b, path)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	return nil, nil
}

// writeDefaultBoilerplateFileは指定されたファイルパスにデフォルトの設定ファイルを書き込む
func writeDefaultBoilerplateFile(path string) error {
	b := []byte(`# costom boilerplate file from sisakulint
	# https://docs.github.com/ja/actions/using-workflows/creating-starter-workflows-for-your-organization
	# https://docs.github.com/en/actions/publishing-packages/publishing-docker-images#publishing-images-to-github-packages
	# https://github.com/docker/metadata-action#semver
name: sisakulint CI

on:
  workflow_dispatch:
  push:
    branches:
      - 'master'
    tags:
      - 'v*'
  pull_request:
    branches:
      - 'master'

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      -
        name: Checkout
        uses: actions/checkout@v4
      -
        name: Docker meta
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: name/app
      -
        name: Login to DockerHub
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      -
        name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
	`)
		if err := os.WriteFile(path, b, 0644); err != nil {
			return fmt.Errorf("failed to write config file %q: %w", path, err)
		}
		return nil
}
