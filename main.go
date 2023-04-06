package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	tempFileName = "trivy-go-plugin-temp.json"
)

func main() {
	trivyCommand := os.Args[1 : len(os.Args)-1]
	tempFilePath := filepath.Join(os.TempDir(), tempFileName)
	defer removeFile(tempFilePath)

	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempFilePath)
	if err := exec.Command("trivy", cmdArgs...).Run(); err != nil {
		log.Fatalf("failed to build report: %v", err)
	}

}
func getScanType() string {
	return os.Args[1]
}
func getOutputFileName() string {
	return os.Args[len(os.Args)-1]
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
