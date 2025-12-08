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
	"os"
	"strings"

	"golang.org/x/term"
)

type Table struct {
	Headers []string
	Rows    [][]string // each row = slice of column cell strings (may contain \n)
}

func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80 // fallback
	}
	return w
}

func wrapCell(cell string, width int) []string {
	// Split on explicit newlines first
	rawLines := strings.Split(cell, "\n")
	var out []string

	for _, line := range rawLines {
		for len(line) > width {
			out = append(out, line[:width])
			line = line[width:]
		}
		out = append(out, line)
	}

	return out
}

func PrintTable(table Table) {
	termWidth := terminalWidth()

	// Find max column widths based on header + data
	colWidths := make([]int, len(table.Headers))
	for i, h := range table.Headers {
		colWidths[i] = len(h)
	}
	for _, row := range table.Rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Reduce column widths so total fits terminal
	totalWidth := len(colWidths) - 1 // account for spaces
	for _, w := range colWidths {
		totalWidth += w
	}

	if totalWidth > termWidth {
		excess := totalWidth - termWidth
		// shrink the widest columns first
		for excess > 0 {
			largest := 0
			idx := 0
			for i, w := range colWidths {
				if w > largest {
					largest = w
					idx = i
				}
			}
			if colWidths[idx] > 10 { // prevent collapsing too much
				colWidths[idx]--
				excess--
			} else {
				break
			}
		}
	}

	// Print header
	for i, h := range table.Headers {
		fmt.Printf("%-*s ", colWidths[i], h)
	}
	fmt.Println()

	// Print separator
	for _, w := range colWidths {
		fmt.Print(strings.Repeat("-", w) + " ")
	}
	fmt.Println()

	// Print rows with wrapping
	for _, row := range table.Rows {
		// compute wrapped lines for each column
		wrapped := make([][]string, len(row))
		maxLines := 1
		for i, cell := range row {
			wrapped[i] = wrapCell(cell, colWidths[i])
			if len(wrapped[i]) > maxLines {
				maxLines = len(wrapped[i])
			}
		}

		// print row line-by-line
		for line := 0; line < maxLines; line++ {
			for col := range colWidths {
				part := ""
				if line < len(wrapped[col]) {
					part = wrapped[col][line]
				}
				fmt.Printf("%-*s ", colWidths[col], part)
			}
			fmt.Println()
		}
	}
}
