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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Ports struct {
	Protocol string
	Port     string
}

func (ports Ports) String() string {
	return fmt.Sprintf("%s/%s", ports.Protocol, ports.Port)
}

// One ingress or egress rule
type RuleView struct {
	Endpoints []string
	Ports     []Ports
}

// A network policy row
type PolicyView struct {
	Kind        string
	Namespace   string
	Name        string
	PodSelector metav1.LabelSelector
	Ingress     []RuleView
	Egress      []RuleView
}

/**************
 * TERMINAL WIDTH
 **************/

func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 100
	}
	return w
}

/**************
 * BUILD SUBCOLUMN CELL (INGRESS/EGRESS)
 **************/

// Convert []RuleView → multiline string with 2 subcolumns per line (EP + Ports)
func BuildRuleCell(rules []RuleView) string {
	var lines []string

	for _, r := range rules {
		max := len(r.Endpoints)
		if len(r.Ports) > max {
			max = len(r.Ports)
		}

		eps := append([]string{}, r.Endpoints...)
		ports := []string{}
		for port := range r.Ports {
			ports = append(ports, r.Ports[port].String())
		}
		pts := append([]string{}, ports...)

		for len(eps) < max {
			eps = append(eps, "")
		}
		for len(pts) < max {
			pts = append(pts, "")
		}

		for i := 0; i < max; i++ {
			// TAB separates mini sub-columns
			lines = append(lines, eps[i]+"\t"+pts[i])
		}
	}

	return strings.Join(lines, "\n")
}

/**************
 * WRAP MULTILINE CELL WITH SUBCOLUMNS
 **************/

func wrapCell(cell string, width int) []string {
	rawLines := strings.Split(cell, "\n")
	var out []string

	// hardcoded subcolumn widths; you can adjust
	endpointWidth := width / 2
	portWidth := width - endpointWidth - 1 // -1 for space between

	for _, line := range rawLines {

		// If using subcolumns (TAB)
		if strings.Contains(line, "\t") {
			parts := strings.SplitN(line, "\t", 2)
			ep := parts[0]
			pt := ""
			if len(parts) > 1 {
				pt = parts[1]
			}

			// wrap endpoint column
			epLines := wrapText(ep, endpointWidth)
			ptLines := wrapText(pt, portWidth)

			max := len(epLines)
			if len(ptLines) > max {
				max = len(ptLines)
			}

			// pad
			for len(epLines) < max {
				epLines = append(epLines, "")
			}
			for len(ptLines) < max {
				ptLines = append(ptLines, "")
			}

			// combine 2 subcolumns
			for i := 0; i < max; i++ {
				out = append(out, fmt.Sprintf("%-*s %-*s",
					endpointWidth, epLines[i],
					portWidth, ptLines[i],
				))
			}

		} else {
			// Regular wrapping
			out = append(out, wrapText(line, width)...)
		}
	}

	return out
}

// Basic wrapper
func wrapText(s string, width int) []string {
	if width < 5 {
		width = 5
	}
	if len(s) <= width {
		return []string{s}
	}

	var out []string
	for len(s) > width {
		out = append(out, s[:width])
		s = s[width:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

/**************
 * COLUMN FILTERING
 **************/

func filterColumns(headers []string, rows [][]string, show []bool) ([]string, [][]string) {
	var newHeaders []string
	var newRows [][]string

	for i, h := range headers {
		if show[i] {
			newHeaders = append(newHeaders, h)
		}
	}

	for _, row := range rows {
		var newRow []string
		for i, cell := range row {
			if show[i] {
				newRow = append(newRow, cell)
			}
		}
		newRows = append(newRows, newRow)
	}

	return newHeaders, newRows
}

/**************
 * TABLE RENDERING
 **************/

func PrintTable(headers []string, rows [][]string) {
	termWidth := terminalWidth()

	colWidths := make([]int, len(headers))

	// Initial width guess
	for i, h := range headers {
		colWidths[i] = len(h)
	}

	// Account for data (measure long lines)
	for _, row := range rows {
		for i, cell := range row {
			for _, l := range strings.Split(cell, "\n") {
				// If subcolumns, measure each separately
				if strings.Contains(l, "\t") {
					parts := strings.SplitN(l, "\t", 2)
					// Sum of subcolumns roughly equals column
					w := len(parts[0]) + len(parts[1]) + 1
					if w > colWidths[i] {
						colWidths[i] = w
					}
				} else {
					if len(l) > colWidths[i] {
						colWidths[i] = len(l)
					}
				}
			}
		}
	}

	// Shrink to fit terminal
	totalWidth := len(colWidths) - 1
	for _, w := range colWidths {
		totalWidth += w
	}

	if totalWidth > termWidth {
		excess := totalWidth - termWidth
		for excess > 0 {
			largest := 0
			idx := 0
			for i, w := range colWidths {
				if w > largest {
					largest = w
					idx = i
				}
			}
			if colWidths[idx] > 10 {
				colWidths[idx]--
				excess--
			} else {
				break
			}
		}
	}

	// Print header
	for i, h := range headers {
		fmt.Printf("%-*s ", colWidths[i], h)
	}
	fmt.Println()

	// Separator
	for _, w := range colWidths {
		fmt.Print(strings.Repeat("-", w), " ")
	}
	fmt.Println()

	// Data rows
	for _, row := range rows {
		wrapped := make([][]string, len(row))
		max := 1

		for i, cell := range row {
			wrapped[i] = wrapCell(cell, colWidths[i])
			if len(wrapped[i]) > max {
				max = len(wrapped[i])
			}
		}

		for line := 0; line < max; line++ {
			for col := range wrapped {
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

type ColumnFilters struct {
	Kind        bool
	Namespace   bool
	Name        bool
	PodSelector bool
	Ingress     bool
	Egress      bool
}

type Column struct {
	Header string
	Enable bool
	Value  func(row PolicyView) string
}

func PoliciesToTableRows(policies []PolicyView, columns []Column) (headers []string, rows [][]string) {

	headers = make([]string, len(columns))
	for i, c := range columns {
		headers[i] = c.Header
	}

	for _, policy := range policies {
		row := make([]string, len(columns))
		for i, c := range columns {
			row[i] = c.Value(policy)
		}
		rows = append(rows, row)
	}

	return headers, rows
}
