package ui

import (
	"encoding/json"
	"fmt"

	"firescan/internal/types"
)

// PrintJSON prints findings in JSON format exactly as in original
func PrintJSON(findings []types.Finding) {
	output, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON output: %v\n", err)
		return
	}
	fmt.Println(string(output))
}