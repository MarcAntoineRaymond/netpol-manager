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

	"slices"

	"github.com/aquasecurity/table"

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

type RuleViewSlice []RuleView

// A network policy row
type PolicyView struct {
	Kind        string
	Namespace   string
	Name        string
	PodSelector metav1.LabelSelector
	Ingress     RuleViewSlice
	Egress      RuleViewSlice
}

func (rs RuleViewSlice) Endpoints() [][]string {
	endpoints := [][]string{}
	for _, r := range rs {
		endpoints = append(endpoints, r.Endpoints)
	}
	return endpoints
}

func (rs RuleViewSlice) Ports() [][]Ports {
	ports := [][]Ports{}
	for _, r := range rs {
		ports = append(ports, r.Ports)
	}
	return ports
}

func RenderTable(headers []string, rows [][]string) {
	t := table.New(os.Stdout)
	t.SetAutoMerge(true)
	t.SetHeaders(headers...)

	for _, row := range rows {
		t.AddRow(row...)
	}

	t.Render()
}

type Column struct {
	Header string
	Enable bool
}

func PoliciesToTableRows(policies []PolicyView, columns []Column) (headers []string, rows [][]string) {

	headers = make([]string, len(columns))
	for i, c := range columns {
		headers[i] = c.Header
	}

	for _, policy := range policies {

		kind := policy.Kind
		namespace := policy.Namespace
		name := policy.Name
		podSelector := metav1.FormatLabelSelector(&policy.PodSelector)
		rowsCount := 1
		if slices.Contains(headers, "INGRESS") && slices.Contains(headers, "EGRESS") {
			rowsCount = max(len(policy.Ingress), len(policy.Egress), 1)
		} else {
			if !slices.Contains(headers, "INGRESS") {
				rowsCount = max(len(policy.Egress), 1)
			} else {
				if !slices.Contains(headers, "EGRESS") {
					rowsCount = max(len(policy.Ingress), 1)
				}
			}
		}

		policyRows := make([][]string, rowsCount)
		baseRow := []string{}
		if slices.Contains(headers, "KIND") {
			baseRow = append(baseRow, kind)
		}
		if slices.Contains(headers, "NAMESPACE") {
			baseRow = append(baseRow, namespace)
		}
		baseRow = append(baseRow, name)
		baseRow = append(baseRow, podSelector)
		for i := range rowsCount {
			policyRows[i] = baseRow
		}
		if slices.Contains(headers, "INGRESS") {
			for j, rule := range policy.Ingress {
				if len(rule.Endpoints) == 0 && len(rule.Ports) == 0 {
					policyRows[j] = append(policyRows[j], "<defaultdeny>")
					policyRows[j] = append(policyRows[j], "")
				} else {
					policyRows[j] = append(policyRows[j], strings.Join(rule.Endpoints, "\n"))
					ports := ""
					for i, port := range rule.Ports {
						if i > 0 {
							ports = fmt.Sprintf("%s\n", ports)
						}
						ports = ports + port.String()
					}
					policyRows[j] = append(policyRows[j], ports)
				}

			}
			// fill columns
			if slices.Contains(headers, "EGRESS") && len(policy.Ingress) < len(policy.Egress) {
				for j := range len(policy.Egress) - len(policy.Ingress) {
					policyRows[j+len(policy.Ingress)] = append(policyRows[j+len(policy.Ingress)], "", "")
				}
			}
		}
		if slices.Contains(headers, "EGRESS") {
			for j, rule := range policy.Egress {
				if len(rule.Endpoints) == 0 && len(rule.Ports) == 0 {
					policyRows[j] = append(policyRows[j], "<defaultdeny>")
					policyRows[j] = append(policyRows[j], "")
				} else {
					policyRows[j] = append(policyRows[j], strings.Join(rule.Endpoints, "\n"))
					ports := ""
					for i, port := range rule.Ports {
						if i > 0 {
							ports = fmt.Sprintf("%s\n", ports)
						}
						ports = ports + port.String()
					}
					policyRows[j] = append(policyRows[j], ports)
				}
			}
		}
		rows = append(rows, policyRows...)
	}

	return headers, rows
}
