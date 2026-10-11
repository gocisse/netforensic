package main

import (
	"fmt"
	"os"

	"github.com/gocisse/netforensic/internal/export"
	"github.com/gocisse/netforensic/internal/models"
)

// csvSuffixes are the names, after the prefix, of the files --export-csv writes.
var csvSuffixes = export.Suffixes

// exportCSV writes the analysis as CSV files for spreadsheets and data
// tools: <prefix>_flows.csv (every flow), <prefix>_issues.csv and
// <prefix>_protocols.csv. It returns the paths written.
func exportCSV(prefix string, res *models.AnalysisResult) ([]string, error) {
	var written []string
	for _, t := range export.Tables(res) {
		path := prefix + t.Suffix
		if err := writeCSVFile(path, t); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func writeCSVFile(path string, t export.Table) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("export csv: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("export csv: %w", cerr)
		}
	}()
	if err := t.Write(f); err != nil {
		return fmt.Errorf("export csv: write %s: %w", path, err)
	}
	return nil
}
