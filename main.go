package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/exp/slices"

	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	tempJsonFileName = "trivy-go-plugin-temp.json"
	version          = "dev"
)

func main() {
	if slices.Contains(os.Args, "-h") || slices.Contains(os.Args, "--help") {
		helpMessage()
	}
	pluginOutput := getFlagValue("--plugin-output")
	if pluginOutput == "" {
		log.Fatal("flag --plugin-output is required")
	}
	trivyOutputFileName := getFlagValue("--output")
	if trivyOutputFileName == "" {
		trivyOutputFileName = filepath.Join(os.TempDir(), tempJsonFileName)
		defer removeFile(trivyOutputFileName)
	}

	if err := makeTrivyJsonReport(trivyOutputFileName); err != nil {
		log.Fatalf("failed to make trivy report: %v", err)
	}
	_, err := getReportFromJson(trivyOutputFileName)
	if err != nil {
		log.Fatalf("failed to get report from json: %v", err)
	}

	if err := saveResult(pluginOutput, []byte{}); err != nil {
		log.Fatalf("failed to save result: %v", err)
	}
}

func getReportFromJson(jsonFileName string) (*types.Report, error) {
	if !isK8s() {
		return readJson[types.Report](jsonFileName)
	}

	k8sParsedReport, err := readJson[k8sReport.Report](jsonFileName)
	if err != nil {
		return nil, err
	}

	var resultsArr types.Results
	for _, vuln := range k8sParsedReport.Vulnerabilities {
		resultsArr = append(resultsArr, vuln.Results...)
	}
	for _, misc := range k8sParsedReport.Misconfigurations {
		resultsArr = append(resultsArr, misc.Results...)
	}
	return &types.Report{
		Results: resultsArr,
	}, nil
}

func readJson[T any](jsonFileName string) (*T, error) {
	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		return nil, err
	}

	defer closeFile(jsonFile)

	var out T
	if err := json.NewDecoder(jsonFile).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func isK8s() bool {
	if slices.Contains(os.Args, "kubernetes") || slices.Contains(os.Args, "k8s") {
		return true
	}
	return false
}

func removeFile(file string) {
	if err := os.Remove(file); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}

func getFlagValue(flag string) string {
	flagIndex := slices.Index(os.Args, flag)
	if flagIndex != -1 && (len(os.Args)-1) > flagIndex { // the flag exists and it is not the last argument
		return os.Args[flagIndex+1]
	}
	return ""
}

func saveResult(filename string, result []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = file.Write(result)
	if err != nil {
		return err
	}
	defer closeFile(file)
	return nil
}

func makeTrivyJsonReport(outputFileName string) error {
	trivyCommand := os.Args[1 : len(os.Args)-2]
	cmdArgs := append(trivyCommand, "--format", "json", "--output", outputFileName)
	cmd := exec.Command("trivy", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func helpMessage() {
	_, err := fmt.Printf(`
trivy-go-plugin v%s
Usage: trivy trivy-go-plugin [-h,--help] command target filename
 A Trivy common plugin.
Options:
  -h, --help    Show usage.
Examples:
  # example
  trivy trivy-go-plugin
`, version)
	if err != nil {
		log.Fatalf("Failed to display help message %v", err)
	}
	os.Exit(0)
}
