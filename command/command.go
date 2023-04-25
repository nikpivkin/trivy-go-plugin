package command

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/exp/slices"
)

func IsHelp() bool {
	return slices.Contains(os.Args, "--help") || slices.Contains(os.Args, "-h")
}

func IsK8s() bool {
	return slices.Contains(os.Args, "kubernetes") || slices.Contains(os.Args, "k8s")
}

func GetPathToPluginDir(fileName string) (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(ex), fileName), nil
}

func GetPathToTemplate(fileName string) (string, error) {
	path, err := GetPathToPluginDir(fileName)
	if err != nil {
		return "", err
	}
	return "@" + path, nil
}

func ReadPluginFile(fileName string) ([]byte, error) {
	path, err := GetPathToPluginDir(fileName)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path)
}

func MakeTrivyJsonReport(outputFileName string) error {
	trivyCommand := os.Args[1 : len(os.Args)-1]
	cmdArgs := append(trivyCommand, "--format", "json", "--output", outputFileName)
	cmd := exec.Command("trivy", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run trivy: %w", err)
	}
	return nil
}

type Arguments map[string]string

func RetrievePluginArguments(availableArguments []string) (pluginArgs Arguments, rest []string) {
	trivyCommand := make([]string, 0, len(os.Args))
	args := make(map[string]string)
	for i := 0; i < len(os.Args); i++ {
		if slices.Contains(availableArguments, os.Args[i]) {
			args[os.Args[i]] = os.Args[i+1]
			i++ // skip argument value
		} else {
			trivyCommand = append(trivyCommand, os.Args[i])
		}
	}
	return args, trivyCommand[1:]
}
