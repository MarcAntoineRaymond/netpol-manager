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
package cmd

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/MarcAntoineRaymond/netpol-manager/helpers"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	ciliumpolicy "github.com/cilium/cilium/pkg/policy/api"
	v1 "k8s.io/api/networking/v1"

	"github.com/spf13/cobra"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var netpolAliases = []string{"netpol", "networkpolicy", "networkpolicies"}
var ciliumNetpolAliases = []string{"cnp", "ciliumnetworkpolicy", "ciliumnetworkpolicies"}
var ciliumClusterwideNetpolAliases = []string{"ccnp", "ciliumclusterwidenetworkpolicy", "ciliumclusterwidenetworkpolicies"}

type GetOptions struct {
	labelSelector string
	kind          string
	podLabels     string
	pod           string
	AllNamespaces bool
	ShowKind      bool
	ShowIngress   bool
	ShowEgress    bool
}

var getOptions *GetOptions

type NetpolSummary struct {
	Kind         string
	Namespace    string
	Name         string
	PodSelector  metav1.LabelSelector
	IngressRules string
	EgressRules  string
}

func init() {
	getOptions = &GetOptions{
		labelSelector: "",
		kind:          "",
		podLabels:     "",
		AllNamespaces: false,
		ShowKind:      false,
		ShowIngress:   true,
		ShowEgress:    true,
	}
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&getOptions.labelSelector, "selector", "l", "", "Label selector (e.g., -l key=value)")
	getCmd.Flags().StringVarP(&getOptions.podLabels, "pod-labels", "p", "", "Pod labels (e.g., -p key=value) prints only network policies that apply to pods with these labels, cannot be used with --pod")
	getCmd.Flags().StringVar(&getOptions.pod, "pod", "", "Prints only network policies that apply to this pod, cannot be used with --pod-labels")
	getCmd.Flags().StringVarP(&getOptions.kind, "kind", "k", "", "Kind of network policy (e.g., NetworkPolicy, CiliumNetworkPolicy) by default both kinds are shown if crd exists")
	getCmd.Flags().BoolVarP(&getOptions.AllNamespaces, "all-namespaces", "A", false, "Get network policies across all namespaces")
	getCmd.Flags().BoolVar(&getOptions.ShowKind, "show-kind", false, "Show resource kind in output")
	getCmd.Flags().BoolVar(&getOptions.ShowIngress, "show-ingress", true, "Show ingress rules in output")
	getCmd.Flags().BoolVar(&getOptions.ShowEgress, "show-egress", true, "Show egress rules in output")
	getCmd.MarkFlagsMutuallyExclusive("pod-labels", "pod")
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get network policies",
	Long: `Get network policies and filter them based on various criteria.
	You can use this command to show network policies of different kinds, filter to what pods they apply, you can reverse the lookup to see what policies apply to a given pod, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := kubernetesOptions.configFlags.ToRESTConfig()
		if err != nil {
			fmt.Println(err)
			return //err
		}

		// Build clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			fmt.Println(err)
			return //err
		}
		ns := ""
		if getOptions.AllNamespaces {
			ns = ""
		} else {
			ns, err = cmd.Flags().GetString("namespace")
			if err != nil {
				fmt.Println(err)
				return //err
			}
			if ns == "" {
				ns, _, err = kubernetesOptions.configFlags.ToRawKubeConfigLoader().Namespace()
				if err != nil {
					fmt.Println(err)
					return //err
				}
			}
		}

		kinds := strings.Split(getOptions.kind, ",")
		var summaries []NetpolSummary

		// List NetworkPolicies
		if HasAllowedKind(kinds, netpolAliases) || getOptions.kind == "" {
			list, err := clientset.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{
				LabelSelector: getOptions.labelSelector,
			})
			if err != nil {
				fmt.Println(err)
				return //err
			}

			summaries = append(summaries, SummarizeNetworkPolicies(list.Items)...)
		}
		hasCnpKind := HasAllowedKind(kinds, ciliumNetpolAliases)
		if hasCnpKind || getOptions.kind == "" {
			// Check for CiliumNetworkPolicies CRD and list if exists
			exists, err := CheckCiliumCRDExists(context.TODO(), config, "ciliumnetworkpolicies.cilium.io")
			if err != nil {
				fmt.Println(err)
				return //err
			}
			if exists || hasCnpKind {
				if !exists {
					fmt.Println("CiliumNetworkPolicy CRD does not exist, but 'CiliumNetworkPolicy' kind was explicitly requested.")
				}
				cnpList, err := ListCiliumNetworkPolicies(context.TODO(), config, ns)
				if err != nil {
					fmt.Println(err)
					return //err
				}

				ciliumSummaries, err := SummarizeCiliumNetworkPolicies(cnpList.Items)
				if err != nil {
					fmt.Println(err)
					return //err
				}

				summaries = append(summaries, ciliumSummaries...)
			}
		}

		hasCcnpKind := HasAllowedKind(kinds, ciliumClusterwideNetpolAliases)
		if hasCcnpKind || getOptions.kind == "" {
			// Check for CiliumNetworkPolicies CRD and list if exists
			exists, err := CheckCiliumCRDExists(context.TODO(), config, "ciliumclusterwidenetworkpolicies.cilium.io")
			if err != nil {
				fmt.Println(err)
				return //err
			}
			if exists || hasCcnpKind {
				if !exists {
					fmt.Println("CiliumClusterWideNetworkPolicy CRD does not exist, but 'CiliumClusterWideNetworkPolicy' kind was explicitly requested.")
				}
				ccnpList, err := ListCiliumClusterWideNetworkPolicies(context.TODO(), config)
				if err != nil {
					fmt.Println(err)
					return //err
				}

				ciliumSummaries, err := SummarizeCiliumClusterWideNetworkPolicies(ccnpList.Items)
				if err != nil {
					fmt.Println(err)
					return //err
				}

				summaries = append(summaries, ciliumSummaries...)
			}
		}

		var filterLabels = getOptions.podLabels

		if getOptions.pod != "" {
			pod, err := clientset.CoreV1().Pods(ns).Get(context.TODO(), getOptions.pod, metav1.GetOptions{})
			if err != nil {
				fmt.Printf("Error retrieving pod %s: %v\n", getOptions.pod, err)
				return //err
			}
			filterLabels = labels.Set(pod.Labels).String()
		}

		if filterLabels != "" {
			var filteredItems []NetpolSummary
			for _, np := range summaries {
				if ok, err := CheckLabelSelectorMatch(filterLabels, np.PodSelector); ok {
					if err != nil {
						fmt.Printf("Error comparing label selectors: %v\n", err)
						return //err
					}
					filteredItems = append(filteredItems, np)
				}
			}
			summaries = filteredItems
		}

		displayNetpolSummaries(summaries)
	},
}

func CheckLabelSelectorMatch(podLabels string, selector metav1.LabelSelector) (bool, error) {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return false, err
	}

	labelSet, err := labels.ConvertSelectorToLabelsMap(podLabels)
	if err != nil {
		return false, err
	}
	return sel.Matches(labelSet), nil
}

func HasAllowedKind(kinds []string, allowedKinds []string) bool {
	for _, kind := range kinds {
		kind = strings.ToLower(kind)
		if slices.Contains(allowedKinds, kind) {
			return true
		}
	}
	return false
}

func SummarizeIngressRules(ingresses []v1.NetworkPolicyIngressRule) string {
	ingressString := ""
	if len(ingresses) == 0 {
		return "/"
	}
	for i, ingress := range ingresses {
		if i > 0 {
			ingressString += "\n"
		}
		peer, ports := SummarizeNetpolRule(ingress.From, ingress.Ports)
		ingressString += fmt.Sprintf("%s<=%s", ports, peer)
	}
	return ingressString
}

func SummarizeEgressRules(egresses []v1.NetworkPolicyEgressRule) string {
	egressString := ""
	if len(egresses) == 0 {
		return "/"
	}
	for i, egress := range egresses {
		if i > 0 {
			egressString += "\n"
		}
		peer, ports := SummarizeNetpolRule(egress.To, egress.Ports)
		egressString += fmt.Sprintf("=>%s : %s", peer, ports)
	}
	return egressString
}

func SummarizeNetpolRule(fromTo []v1.NetworkPolicyPeer, ports []v1.NetworkPolicyPort) (string, string) {
	peerString := ""
	portString := ""
	for i, peer := range fromTo {
		if i > 0 {
			peerString += ", "
		}
		if peer.NamespaceSelector != nil {
			peerString += strings.Split(metav1.FormatLabelSelector(peer.NamespaceSelector), "=")[1] + "/"
		}
		if peer.PodSelector != nil {
			peerString += metav1.FormatLabelSelector(peer.PodSelector)
		}
		if peer.IPBlock != nil {
			peerString += peer.IPBlock.CIDR
		}
	}
	for i, port := range ports {
		if i > 0 {
			portString += ", "
		}
		if port.Port != nil {
			portString += port.Port.String()
		}
		if port.Protocol != nil {
			portString += "/" + string(*port.Protocol)
		}
	}
	if peerString == "" && portString == "" {
		peerString = "X"
	}
	return peerString, portString
}

func SummarizeCiliumIngressRules(ingresses []ciliumpolicy.IngressRule, ingressesDeny []ciliumpolicy.IngressDenyRule) string {
	ingressString := ""
	if len(ingresses) == 0 {
		return "/"
	}
	for i, ingress := range ingresses {
		if i > 0 {
			ingressString += "\n"
		}
		cidrRule := []ciliumpolicy.CIDRRule{}
		for _, cidr := range ingress.FromCIDR {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr: cidr,
			})
		}
		for _, cidr := range ingress.FromCIDRSet {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr:        cidr.Cidr,
				ExceptCIDRs: cidr.ExceptCIDRs,
			})
		}
		ciliumRule := CiliumNetpolRule{
			Endpoints: ingress.FromEndpoints,
			Entities:  ingress.FromEntities,
			Cidr:      cidrRule,
			Fqdn:      []ciliumpolicy.FQDNSelector{},
		}
		peer, ports := SummarizeCiliumNetpolRule(ciliumRule, ingress.ToPorts)
		ingressString += fmt.Sprintf("%s<=%s", ports, peer)
	}
	for i, ingressDeny := range ingressesDeny {
		if i > 0 || len(ingresses) > 0 {
			ingressString += "\n"
		}
		cidrRule := []ciliumpolicy.CIDRRule{}
		for _, cidr := range ingressDeny.FromCIDR {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr: cidr,
			})
		}
		for _, cidr := range ingressDeny.FromCIDRSet {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr:        cidr.Cidr,
				ExceptCIDRs: cidr.ExceptCIDRs,
			})
		}
		ciliumRule := CiliumNetpolRule{
			Endpoints: ingressDeny.FromEndpoints,
			Entities:  ingressDeny.FromEntities,
			Cidr:      cidrRule,
			Fqdn:      []ciliumpolicy.FQDNSelector{},
		}
		portRule := ciliumpolicy.PortRules{}
		for _, port := range ingressDeny.ToPorts {
			portRule = append(portRule, ciliumpolicy.PortRule{
				Ports: port.Ports,
			})
		}
		peer, ports := SummarizeCiliumNetpolRule(ciliumRule, portRule)
		ingressString += fmt.Sprintf("<deny> %s<=%s", ports, peer)
	}
	return ingressString
}

func SummarizeCiliumEgressRules(egresses []ciliumpolicy.EgressRule, egressesDeny []ciliumpolicy.EgressDenyRule) string {
	egressString := ""
	if len(egresses) == 0 {
		return "/"
	}
	for i, egress := range egresses {
		if i > 0 {
			egressString += "\n"
		}
		cidrRule := []ciliumpolicy.CIDRRule{}
		for _, cidr := range egress.ToCIDR {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr: cidr,
			})
		}
		for _, cidr := range egress.ToCIDRSet {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr:        cidr.Cidr,
				ExceptCIDRs: cidr.ExceptCIDRs,
			})
		}
		ciliumRule := CiliumNetpolRule{
			Endpoints: egress.ToEndpoints,
			Entities:  egress.ToEntities,
			Cidr:      cidrRule,
			Fqdn:      egress.ToFQDNs,
		}
		peer, ports := SummarizeCiliumNetpolRule(ciliumRule, egress.ToPorts)
		egressString += fmt.Sprintf("=>%s : %s", peer, ports)
	}
	for i, egressDeny := range egressesDeny {
		if i > 0 || len(egresses) > 0 {
			egressString += "\n"
		}
		cidrRule := []ciliumpolicy.CIDRRule{}
		for _, cidr := range egressDeny.ToCIDR {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr: cidr,
			})
		}
		for _, cidr := range egressDeny.ToCIDRSet {
			cidrRule = append(cidrRule, ciliumpolicy.CIDRRule{
				Cidr:        cidr.Cidr,
				ExceptCIDRs: cidr.ExceptCIDRs,
			})
		}
		ciliumRule := CiliumNetpolRule{
			Endpoints: egressDeny.ToEndpoints,
			Entities:  egressDeny.ToEntities,
			Cidr:      cidrRule,
			Fqdn:      []ciliumpolicy.FQDNSelector{},
		}
		portRule := ciliumpolicy.PortRules{}
		for _, port := range egressDeny.ToPorts {
			portRule = append(portRule, ciliumpolicy.PortRule{
				Ports: port.Ports,
			})
		}
		peer, ports := SummarizeCiliumNetpolRule(ciliumRule, portRule)
		egressString += fmt.Sprintf("<deny>=>%s : %s", peer, ports)
	}
	return egressString
}

type CiliumNetpolRule struct {
	Endpoints []ciliumpolicy.EndpointSelector
	Entities  []ciliumpolicy.Entity
	Cidr      []ciliumpolicy.CIDRRule
	Fqdn      []ciliumpolicy.FQDNSelector
}

func SummarizeCiliumNetpolRule(ciliumRule CiliumNetpolRule, ports ciliumpolicy.PortRules) (string, string) {
	peerString := ""
	portString := ""

	for i, endpoint := range ciliumRule.Endpoints {
		if i > 0 {
			peerString += ", "
		}
		labelSel, err := ConvertEndpointSelectorToLabelSelector(endpoint)
		if err != nil {
			fmt.Println("Error converting endpoint selector to label selector:", err)
			peerString += "<invalid endpoint selector>"
		}

		if namespace, ok := labelSel.MatchLabels["io.kubernetes.pod.namespace"]; ok {
			peerString += namespace + "/"
			delete(labelSel.MatchLabels, "io.kubernetes.pod.namespace")
		}

		peerString += metav1.FormatLabelSelector(labelSel)
	}
	for i, entity := range ciliumRule.Entities {
		if i > 0 {
			peerString += ", "
		}
		peerString += "(" + string(entity) + ")"
	}
	for i, cidr := range ciliumRule.Cidr {
		if i > 0 {
			peerString += ", "
		}
		peerString += string(cidr.Cidr)
		if len(cidr.ExceptCIDRs) > 0 {
			peerString += "-" + ciliumpolicy.CIDRSlice(cidr.ExceptCIDRs).String()
		}
	}
	for i, fqdn := range ciliumRule.Fqdn {
		if i > 0 {
			peerString += ", "
		}
		peerString += fqdn.String()
	}

	for i, port := range ports {
		if i > 0 {
			portString += ", "
		}
		for i, p := range port.Ports {
			if i > 0 {
				portString += ", "
			}
			portString += p.Port
			if p.EndPort != 0 {
				portString += fmt.Sprintf("-%d", p.EndPort)
			}
			if p.Protocol != "" {
				portString += "/" + string(p.Protocol)
			}
		}
	}

	if peerString == "" && portString == "" {
		peerString = "X"
	}

	return peerString, portString
}

func SummarizeNetworkPolicies(nps []v1.NetworkPolicy) []NetpolSummary {
	summaries := []NetpolSummary{}
	for _, np := range nps {
		if slices.Contains(np.Spec.PolicyTypes, v1.PolicyTypeIngress) && np.Spec.Ingress == nil {
			np.Spec.Ingress = []v1.NetworkPolicyIngressRule{
				v1.NetworkPolicyIngressRule{},
			}
		}
		if slices.Contains(np.Spec.PolicyTypes, v1.PolicyTypeEgress) && np.Spec.Egress == nil {
			np.Spec.Egress = []v1.NetworkPolicyEgressRule{
				v1.NetworkPolicyEgressRule{},
			}
		}
		summary := NetpolSummary{
			Kind:         "NetworkPolicy",
			Namespace:    np.Namespace,
			Name:         np.Name,
			PodSelector:  np.Spec.PodSelector,
			IngressRules: SummarizeIngressRules(np.Spec.Ingress),
			EgressRules:  SummarizeEgressRules(np.Spec.Egress),
		}
		summaries = append(summaries, summary)
	}
	return summaries
}

func SummarizeCiliumNetworkPolicies(nps []ciliumv2.CiliumNetworkPolicy) ([]NetpolSummary, error) {
	summaries := []NetpolSummary{}
	for _, np := range nps {
		selectors, err := ConvertEndpointSelectorToLabelSelector(np.Spec.EndpointSelector)
		if err != nil {
			return []NetpolSummary{}, err
		}
		summary := NetpolSummary{
			Kind:         np.Kind,
			Namespace:    np.Namespace,
			Name:         np.Name,
			PodSelector:  *selectors,
			IngressRules: SummarizeCiliumIngressRules(np.Spec.Ingress, np.Spec.IngressDeny),
			EgressRules:  SummarizeCiliumEgressRules(np.Spec.Egress, np.Spec.EgressDeny),
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func SummarizeCiliumClusterWideNetworkPolicies(nps []ciliumv2.CiliumClusterwideNetworkPolicy) ([]NetpolSummary, error) {
	summaries := []NetpolSummary{}
	for _, np := range nps {
		selectors, err := ConvertEndpointSelectorToLabelSelector(np.Spec.EndpointSelector)
		if err != nil {
			return []NetpolSummary{}, err
		}
		if !np.Spec.NodeSelector.IsZero() {
			// Skip policies that apply to nodes
			continue
		}
		summary := NetpolSummary{
			Kind:         np.Kind,
			Namespace:    "*",
			Name:         np.Name,
			PodSelector:  *selectors,
			IngressRules: SummarizeCiliumIngressRules(np.Spec.Ingress, np.Spec.IngressDeny),
			EgressRules:  SummarizeCiliumEgressRules(np.Spec.Egress, np.Spec.EgressDeny),
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}

func ConvertEndpointSelectorToLabelSelector(es ciliumpolicy.EndpointSelector) (*metav1.LabelSelector, error) {
	ls := &metav1.LabelSelector{
		MatchLabels:      es.MatchLabels,
		MatchExpressions: []metav1.LabelSelectorRequirement{},
	}

	for _, lbl := range es.MatchExpressions {
		req := metav1.LabelSelectorRequirement{
			Key:      lbl.Key,
			Operator: metav1.LabelSelectorOperator(lbl.Operator),
			Values:   lbl.Values,
		}
		ls.MatchExpressions = append(ls.MatchExpressions, req)
	}

	return ls, nil
}

type Column struct {
	Header string
	Enable bool
	Value  func(row NetpolSummary) string
}

func displayNetpolSummaries(nps []NetpolSummary) {
	cols := []Column{
		{Header: "KIND", Enable: getOptions.ShowKind, Value: func(r NetpolSummary) string {
			return r.Kind
		}},
		{Header: "NAMESPACE", Enable: getOptions.AllNamespaces, Value: func(r NetpolSummary) string {
			return r.Namespace
		}},
		{Header: "NAME", Enable: true, Value: func(r NetpolSummary) string {
			return r.Name
		}},
		{Header: "POD-SELECTOR", Enable: true, Value: func(r NetpolSummary) string {
			return metav1.FormatLabelSelector(&r.PodSelector)
		}},
		{Header: "INGRESS", Enable: getOptions.ShowIngress, Value: func(r NetpolSummary) string {
			return r.IngressRules
		}},
		{Header: "EGRESS", Enable: getOptions.ShowEgress, Value: func(r NetpolSummary) string {
			return r.EgressRules
		}},
	}

	var activeCols []Column
	for _, c := range cols {
		if c.Enable {
			activeCols = append(activeCols, c)
		}
	}

	headers := make([]string, len(activeCols))
	for i, c := range activeCols {
		headers[i] = c.Header
	}

	var tableRows [][]string
	for _, np := range nps {
		row := make([]string, len(activeCols))
		for i, c := range activeCols {
			row[i] = c.Value(np)
		}
		tableRows = append(tableRows, row)
	}
	table := helpers.Table{
		Headers: headers,
		Rows:    tableRows,
	}
	helpers.PrintTable(table)
}

func CheckCiliumCRDExists(ctx context.Context, config *rest.Config, crdName string) (bool, error) {
	extClient, err := apiextclient.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to create API extensions client: %w", err)
	}

	_, err = extClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crdName, metav1.GetOptions{})
	if err != nil {
		return false, nil
	}
	return true, nil
}

func ListCiliumNetworkPolicies(
	ctx context.Context,
	config *rest.Config,
	namespace string,
) (*ciliumv2.CiliumNetworkPolicyList, error) {

	ciliumClient, err := ciliumclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cilium clientset: %w", err)
	}

	cnps, err := ciliumClient.CiliumV2().CiliumNetworkPolicies(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: getOptions.labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list CiliumNetworkPolicies: %w", err)
	}

	return cnps, nil
}

func ListCiliumClusterWideNetworkPolicies(
	ctx context.Context,
	config *rest.Config,
) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {

	ciliumClient, err := ciliumclientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cilium clientset: %w", err)
	}

	ccnps, err := ciliumClient.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, metav1.ListOptions{
		LabelSelector: getOptions.labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list CiliumNetworkPolicies: %w", err)
	}

	return ccnps, nil
}
