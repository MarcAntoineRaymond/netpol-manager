/*
Copyright 2025 Marc-Antoine RAYMOND.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package helpers

import (
	"fmt"
	"strings"
)

type Table struct {
	Headers []string
	Rows    [][]string // each row = slice of column cell strings (may contain \n)
}

func PrintMultilineTable(t Table) {
	colWidths := make([]int, len(t.Headers))

	splitRows := make([][][]string, len(t.Rows))
	for i, row := range t.Rows {
		splitRows[i] = make([][]string, len(row))
		for colIdx, cell := range row {
			lines := strings.Split(cell, "\n")
			splitRows[i][colIdx] = lines
			for _, ln := range lines {
				if len(ln) > colWidths[colIdx] {
					colWidths[colIdx] = len(ln)
				}
			}
		}
	}

	for i, h := range t.Headers {
		if len(h) > colWidths[i] {
			colWidths[i] = len(h)
		}
	}

	for i, h := range t.Headers {
		fmt.Printf("%-*s   ", colWidths[i], h)
	}
	fmt.Println()

	for _, row := range splitRows {
		maxLines := 1
		for _, cellLines := range row {
			if len(cellLines) > maxLines {
				maxLines = len(cellLines)
			}
		}

		for line := 0; line < maxLines; line++ {
			for colIdx, cellLines := range row {
				var text string
				if line < len(cellLines) {
					text = cellLines[line]
				} else {
					text = ""
				}
				fmt.Printf("%-*s   ", colWidths[colIdx], text)
			}
			fmt.Println()
		}
	}
}
