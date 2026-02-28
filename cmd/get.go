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
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/MarcAntoineRaymond/netpol-manager/helpers"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	ciliumpolicy "github.com/cilium/cilium/pkg/policy/api"
	"go.yaml.in/yaml/v3"
	v1 "k8s.io/api/networking/v1"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var netpolAliases = []string{"netpol", "networkpolicy", "networkpolicies"}
var ciliumNetpolAliases = []string{"cnp", "ciliumnetworkpolicy", "ciliumnetworkpolicies"}
var ciliumClusterwideNetpolAliases = []string{"ccnp", "ciliumclusterwidenetworkpolicy", "ciliumclusterwidenetworkpolicies"}
var allowedOutputFormats = []string{"table", "name", "json", "yaml"}

type GetOptions struct {
	labelSelector     string
	kind              string
	podLabels         string
	pod               string
	allNamespaces     bool
	showKind          bool
	showIngress       bool
	showEgress        bool
	outputFormat      string
	showManagedFields bool
}

var getOptions *GetOptions

func init() {
	getOptions = &GetOptions{
		labelSelector:     "",
		kind:              "",
		podLabels:         "",
		allNamespaces:     false,
		showKind:          false,
		showIngress:       true,
		showEgress:        true,
		outputFormat:      "table",
		showManagedFields: false,
	}
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&getOptions.labelSelector, "selector", "l", "", "Label selector (e.g., -l key=value)")
	getCmd.Flags().StringVarP(&getOptions.podLabels, "pod-labels", "p", "", "Pod labels (e.g., -p key=value) prints only network policies that apply to pods with these labels, cannot be used with --pod")
	getCmd.Flags().StringVar(&getOptions.pod, "pod", "", "Prints only network policies that apply to this pod, cannot be used with --pod-labels")
	getCmd.Flags().StringVarP(&getOptions.kind, "kind", "k", "", "Kind of network policy (e.g., NetworkPolicy, CiliumNetworkPolicy) by default both kinds are shown if crd exists")
	getCmd.Flags().BoolVarP(&getOptions.allNamespaces, "all-namespaces", "A", false, "Get network policies across all namespaces")
	getCmd.Flags().BoolVar(&getOptions.showKind, "show-kind", false, "Show resource kind in output")
	getCmd.Flags().BoolVar(&getOptions.showIngress, "show-ingress", true, "Show ingress rules in output")
	getCmd.Flags().BoolVar(&getOptions.showEgress, "show-egress", true, "Show egress rules in output")
	getCmd.Flags().StringVarP(&getOptions.outputFormat, "output", "o", "table", "Output format, must be one of table (default), name, json, yaml")
	getCmd.Flags().BoolVar(&getOptions.showManagedFields, "show-managed-fields", false, "If true, keep the managedFields when printing objects in JSON or YAML format.")
	getCmd.MarkFlagsMutuallyExclusive("pod-labels", "pod")
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get network policies",
	Long: `Get network policies and filter them based on various criteria.
	You can use this command to show network policies of different kinds, filter to what pods they apply, you can reverse the lookup to see what policies apply to a given pod, and more.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := kubernetesOptions.configFlags.ToRESTConfig()
		if err != nil {
			return err
		}

		// Build clientset
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return err
		}
		ns := ""
		if getOptions.allNamespaces {
			ns = ""
		} else {
			ns, err = cmd.Flags().GetString("namespace")
			if err != nil {
				return err
			}
			if ns == "" {
				ns, _, err = kubernetesOptions.configFlags.ToRawKubeConfigLoader().Namespace()
				if err != nil {
					return err
				}
			}
		}

		if !slices.Contains(allowedOutputFormats, getOptions.outputFormat) {
			return fmt.Errorf("Invalid output format: %s. Allowed formats are: %s\n", getOptions.outputFormat, strings.Join(allowedOutputFormats, ", "))
		}

		kinds := strings.Split(getOptions.kind, ",")
		var policyViews []helpers.PolicyView
		policyList := &corev1.List{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "List",
			},
			ListMeta: metav1.ListMeta{
				ResourceVersion: "",
			},
		}

		// List NetworkPolicies
		if HasAllowedKind(kinds, netpolAliases) || getOptions.kind == "" {
			list, err := clientset.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{
				LabelSelector: getOptions.labelSelector,
			})
			if err != nil {
				return err
			}

			for _, np := range list.Items {
				unstructuredObj, err := PrepareUnstructured(np)
				if err != nil {
					return err
				}
				policyList.Items = append(policyList.Items, runtime.RawExtension{
					Object: unstructuredObj,
				})
				policyViews = append(policyViews, NetworkPolicyToView(np))
			}
		}
		hasCnpKind := HasAllowedKind(kinds, ciliumNetpolAliases)
		if hasCnpKind || getOptions.kind == "" {
			// Check for CiliumNetworkPolicies CRD and list if exists
			exists, err := CheckCiliumCRDExists(context.TODO(), config, "ciliumnetworkpolicies.cilium.io")
			if err != nil {
				return err
			}
			if exists || hasCnpKind {
				if !exists {
					fmt.Println("CiliumNetworkPolicy CRD does not exist, but 'CiliumNetworkPolicy' kind was explicitly requested.")
				}
				cnpList, err := ListCiliumNetworkPolicies(context.TODO(), config, ns)
				if err != nil {
					return err
				}

				for _, cnp := range cnpList.Items {
					unstructuredObj, err := PrepareUnstructured(cnp)
					if err != nil {
						return err
					}
					policyList.Items = append(policyList.Items, runtime.RawExtension{
						Object: unstructuredObj,
					})
					policyViews = append(policyViews, CiliumNetworkPolicyToView(cnp))
				}
			}
		}

		hasCcnpKind := HasAllowedKind(kinds, ciliumClusterwideNetpolAliases)
		if hasCcnpKind || getOptions.kind == "" {
			// Check for CiliumNetworkPolicies CRD and list if exists
			exists, err := CheckCiliumCRDExists(context.TODO(), config, "ciliumclusterwidenetworkpolicies.cilium.io")
			if err != nil {
				return err
			}
			if exists || hasCcnpKind {
				if !exists {
					fmt.Println("CiliumClusterWideNetworkPolicy CRD does not exist, but 'CiliumClusterWideNetworkPolicy' kind was explicitly requested.")
				}
				ccnpList, err := ListCiliumClusterWideNetworkPolicies(context.TODO(), config)
				if err != nil {
					return err
				}

				for _, ccnp := range ccnpList.Items {
					if ccnp.Spec.EndpointSelector.IsZero() {
						// Skip host policies
						continue
					}
					unstructuredObj, err := PrepareUnstructured(ccnp)
					if err != nil {
						return err
					}
					policyList.Items = append(policyList.Items, runtime.RawExtension{
						Object: unstructuredObj,
					})
					policyViews = append(policyViews, CiliumClusterWideNetworkPolicyToView(ccnp))
				}
			}
		}

		var filterLabels = getOptions.podLabels

		if getOptions.pod != "" {
			pod, err := clientset.CoreV1().Pods(ns).Get(context.TODO(), getOptions.pod, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("Error retrieving pod %s: %v\n", getOptions.pod, err)
			}
			filterLabels = labels.Set(pod.Labels).String()
		}

		if filterLabels != "" {
			var filteredItems []helpers.PolicyView
			for _, np := range policyViews {
				if ok, err := CheckLabelSelectorMatch(filterLabels, np.PodSelector); ok {
					if err != nil {
						return fmt.Errorf("Error comparing label selectors: %v\n", err)
					}
					filteredItems = append(filteredItems, np)
				}
			}
			policyViews = filteredItems
		}

		if getOptions.outputFormat == "json" {

			b, err := json.Marshal(policyList)
			if err != nil {
				return err
			}
			fmt.Println(string(b))
			return nil
		}
		if getOptions.outputFormat == "yaml" {

			b, err := json.Marshal(policyList)
			if err != nil {
				return err
			}
			var out map[string]interface{}
			err = json.Unmarshal(b, &out)
			if err != nil {
				return err
			}
			yamlBytes, err := yaml.Marshal(out)
			if err != nil {
				return err
			}
			fmt.Println(string(yamlBytes))
			return nil
		}
		if getOptions.outputFormat == "name" {
			for _, np := range policyViews {
				if getOptions.allNamespaces {
					fmt.Printf("%s/%s/%s\n", np.Kind, np.Namespace, np.Name)
				} else {
					fmt.Printf("%s/%s\n", np.Kind, np.Name)
				}
			}
			return nil
		}

		// Default to table output
		displayPolicies(policyViews)
		return nil
	},
}

func PrepareUnstructured(obj any) (runtime.Unstructured, error) {
	u := &unstructured.Unstructured{}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &u.Object); err != nil {
		return nil, err
	}

	if !getOptions.showManagedFields {
		unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	}
	return u, nil
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

func buildRuleViewFromNetpolRules(fromTo []v1.NetworkPolicyPeer, ports []v1.NetworkPolicyPort) helpers.RuleView {
	peerEndpoints := []string{}
	peerPorts := []helpers.Ports{}
	for _, peer := range fromTo {
		if peer.NamespaceSelector != nil {
			peerEndpoints = append(peerEndpoints, strings.Split(metav1.FormatLabelSelector(peer.NamespaceSelector), "=")[1]+"/")
		}
		if peer.PodSelector != nil {
			peerEndpoints = append(peerEndpoints, metav1.FormatLabelSelector(peer.PodSelector))
		}
		if peer.IPBlock != nil {
			peerEndpoints = append(peerEndpoints, peer.IPBlock.CIDR)
		}
	}
	for _, port := range ports {
		p := helpers.Ports{}
		if port.Port != nil {
			p.Port = port.Port.String()
		}
		if port.Protocol != nil {
			p.Protocol = string(*port.Protocol)
		} else {
			p.Protocol = "TCP"
		}
		peerPorts = append(peerPorts, p)
	}
	return helpers.RuleView{
		Endpoints: peerEndpoints,
		Ports:     peerPorts,
	}
}

func NetworkPolicyToView(np v1.NetworkPolicy) helpers.PolicyView {
	ingress := []helpers.RuleView{}
	egress := []helpers.RuleView{}

	for _, rule := range np.Spec.Ingress {
		ingress = append(ingress, buildRuleViewFromNetpolRules(rule.From, rule.Ports))
	}

	for _, rule := range np.Spec.Egress {
		egress = append(egress, buildRuleViewFromNetpolRules(rule.To, rule.Ports))
	}

	return helpers.PolicyView{
		Kind:        "NetworkPolicy",
		Namespace:   np.Namespace,
		Name:        np.Name,
		PodSelector: np.Spec.PodSelector,
		Ingress:     ingress,
		Egress:      egress,
	}
}

func CiliumNetworkPolicyToView(cnp ciliumv2.CiliumNetworkPolicy) helpers.PolicyView {
	selectors, err := ConvertEndpointSelectorToLabelSelector(cnp.Spec.EndpointSelector)
	if err != nil {
		fmt.Println("Error converting endpoint selector to label selector:", err)
	}
	return helpers.PolicyView{
		Kind:        cnp.Kind,
		Namespace:   cnp.Namespace,
		Name:        cnp.Name,
		PodSelector: *selectors,
		Ingress:     buildRuleViewFromCiliumIngressRules(cnp.Spec.Ingress, cnp.Spec.IngressDeny),
		Egress:      buildRuleViewFromCiliumEgressRules(cnp.Spec.Egress, cnp.Spec.EgressDeny),
	}
}

func CiliumClusterWideNetworkPolicyToView(ccnp ciliumv2.CiliumClusterwideNetworkPolicy) helpers.PolicyView {
	selectors, err := ConvertEndpointSelectorToLabelSelector(ccnp.Spec.EndpointSelector)
	if err != nil {
		fmt.Println("Error converting endpoint selector to label selector:", err)
	}
	return helpers.PolicyView{
		Kind:        ccnp.Kind,
		Namespace:   "*",
		Name:        ccnp.Name,
		PodSelector: *selectors,
		Ingress:     buildRuleViewFromCiliumIngressRules(ccnp.Spec.Ingress, ccnp.Spec.IngressDeny),
		Egress:      buildRuleViewFromCiliumEgressRules(ccnp.Spec.Egress, ccnp.Spec.EgressDeny),
	}
}

func buildRuleViewFromCiliumIngressRules(ingresses []ciliumpolicy.IngressRule, ingressesDeny []ciliumpolicy.IngressDenyRule) []helpers.RuleView {
	rules := []helpers.RuleView{}
	if len(ingresses) == 0 && len(ingressesDeny) == 0 {
		return rules
	}
	for _, ingress := range ingresses {
		peerEndpoints := []string{}
		peerPorts := []helpers.Ports{}
		if ingress.FromCIDR != nil {
			peerEndpoints = append(peerEndpoints, ingress.FromCIDR.String())
		}
		for _, cidr := range ingress.FromCIDRSet {
			peerEndpoints = append(peerEndpoints, cidr.String())
		}
		for _, from := range ingress.FromEndpoints {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(from)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<invalid endpoint selector>"
			} else {
				if namespace, ok := labelSel.MatchLabels["io.kubernetes.pod.namespace"]; ok {
					peerString += namespace + "/"
					delete(labelSel.MatchLabels, "io.kubernetes.pod.namespace")
				}
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		for _, entity := range ingress.FromEntities {
			peerEndpoints = append(peerEndpoints, "("+string(entity)+")")
		}
		for groupname, _ := range ingress.FromGroups {
			peerEndpoints = append(peerEndpoints, "<group>:"+strconv.Itoa(groupname))
		}
		for _, nodes := range ingress.FromNodes {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(nodes)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<nodes>:<invalid endpoint selector>"
			} else {
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, "<nodes>:"+peerString)
		}
		for _, icmp := range ingress.ICMPs {
			var peerStringIpv4 string
			var peerStringIpv6 string
			var peerString string
			for _, t := range icmp.Fields {
				if t.Family == "IPv4" {
					if peerStringIpv4 != "" {
						peerStringIpv4 += ","
					}
					peerStringIpv4 += t.Type.String()
				} else if t.Family == "IPv6" {
					if peerStringIpv6 != "" {
						peerStringIpv6 += ","
					}
					peerStringIpv6 += t.Type.String()
				}
			}
			if peerStringIpv4 != "" {
				peerString += "<icmp/IPv4>:" + peerStringIpv4
			}
			if peerStringIpv6 != "" {
				peerString += "<icmp/IPv6>:" + peerStringIpv6
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		if ingress.Authentication != nil {
			peerEndpoints = append(peerEndpoints, "<authentication>:"+string(ingress.Authentication.Mode))
		}
		for _, port := range ingress.ToPorts {
			for _, p := range port.Ports {
				proto := string(p.Protocol)
				if proto == "" {
					proto = "ANY"
				}
				peerPorts = append(peerPorts, helpers.Ports{
					Port:     p.Port,
					Protocol: proto,
				})
			}
		}
		if len(peerEndpoints) == 0 && len(peerPorts) == 0 {
			peerEndpoints = append(peerEndpoints, "<defaultdeny>")
		}
		rules = append(rules, helpers.RuleView{
			Endpoints: peerEndpoints,
			Ports:     peerPorts,
		})
	}

	for _, ingressDeny := range ingressesDeny {
		peerEndpoints := []string{}
		peerPorts := []helpers.Ports{}
		if ingressDeny.FromCIDR != nil {
			peerEndpoints = append(peerEndpoints, ingressDeny.FromCIDR.String())
		}
		for _, cidr := range ingressDeny.FromCIDRSet {
			peerEndpoints = append(peerEndpoints, cidr.String())
		}
		for _, from := range ingressDeny.FromEndpoints {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(from)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<invalid endpoint selector>"
			} else {
				if namespace, ok := labelSel.MatchLabels["io.kubernetes.pod.namespace"]; ok {
					peerString += namespace + "/"
					delete(labelSel.MatchLabels, "io.kubernetes.pod.namespace")
				}
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		for _, entity := range ingressDeny.FromEntities {
			peerEndpoints = append(peerEndpoints, "("+string(entity)+")")
		}
		for _, port := range ingressDeny.ToPorts {
			for _, p := range port.Ports {
				proto := string(p.Protocol)
				if proto == "" {
					proto = "ANY"
				}
				peerPorts = append(peerPorts, helpers.Ports{
					Port:     p.Port,
					Protocol: proto,
				})
			}
		}
		peerEndpoints[0] = "<deny>" + peerEndpoints[0]
		rules = append(rules, helpers.RuleView{
			Endpoints: peerEndpoints,
			Ports:     peerPorts,
		})
	}
	return rules
}

func buildRuleViewFromCiliumEgressRules(egresses []ciliumpolicy.EgressRule, egressesDeny []ciliumpolicy.EgressDenyRule) []helpers.RuleView {
	rules := []helpers.RuleView{}
	if len(egresses) == 0 && len(egressesDeny) == 0 {
		return rules
	}
	for _, egress := range egresses {
		peerEndpoints := []string{}
		peerPorts := []helpers.Ports{}
		if egress.ToCIDR != nil {
			peerEndpoints = append(peerEndpoints, egress.ToCIDR.String())
		}
		for _, cidr := range egress.ToCIDRSet {
			peerEndpoints = append(peerEndpoints, cidr.String())
		}
		for _, fqdn := range egress.ToFQDNs {
			if fqdn.MatchName != "" {
				peerEndpoints = append(peerEndpoints, fqdn.MatchName)
			}
			if fqdn.MatchPattern != "" {
				peerEndpoints = append(peerEndpoints, fqdn.MatchPattern)
			}
		}
		for _, from := range egress.ToEndpoints {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(from)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<invalid endpoint selector>"
			} else {
				if namespace, ok := labelSel.MatchLabels["io.kubernetes.pod.namespace"]; ok {
					peerString += namespace + "/"
					delete(labelSel.MatchLabels, "io.kubernetes.pod.namespace")
				}
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		for _, entity := range egress.ToEntities {
			peerEndpoints = append(peerEndpoints, "("+string(entity)+")")
		}
		for _, svc := range egress.ToServices {
			if svc.K8sServiceSelector != nil {
				var peerString string
				labelSel, err := ConvertEndpointSelectorToLabelSelector(ciliumpolicy.EndpointSelector(svc.K8sServiceSelector.Selector))
				if err != nil {
					fmt.Println("Error converting endpoint selector to label selector:", err)
					peerString += "<invalid endpoint selector>"
				} else {
					if svc.K8sServiceSelector.Namespace != "" {
						peerString += svc.K8sServiceSelector.Namespace + "/"
					}
					peerString += metav1.FormatLabelSelector(labelSel)
				}
				peerEndpoints = append(peerEndpoints, "<service>:"+peerString)
			}
			if svc.K8sService != nil {
				if svc.K8sService.Namespace != "" {
					peerEndpoints = append(peerEndpoints, "<service>:"+svc.K8sService.Namespace+"/"+svc.K8sService.ServiceName)
				} else {
					peerEndpoints = append(peerEndpoints, "<service>:"+svc.K8sService.ServiceName)
				}
			}
		}
		for groupname, _ := range egress.ToGroups {
			peerEndpoints = append(peerEndpoints, "<group>:"+strconv.Itoa(groupname))
		}
		for _, nodes := range egress.ToNodes {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(nodes)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<nodes>:<invalid endpoint selector>"
			} else {
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, "<nodes>:"+peerString)
		}
		for _, icmp := range egress.ICMPs {
			var peerStringIpv4 string
			var peerStringIpv6 string
			var peerString string
			for _, t := range icmp.Fields {
				if t.Family == "IPv4" {
					if peerStringIpv4 != "" {
						peerStringIpv4 += ","
					}
					peerStringIpv4 += t.Type.String()
				} else if t.Family == "IPv6" {
					if peerStringIpv6 != "" {
						peerStringIpv6 += ","
					}
					peerStringIpv6 += t.Type.String()
				}
			}
			if peerStringIpv4 != "" {
				peerString += "<icmp/IPv4>:" + peerStringIpv4
			}
			if peerStringIpv6 != "" {
				peerString += "<icmp/IPv6>:" + peerStringIpv6
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		if egress.Authentication != nil {
			peerEndpoints = append(peerEndpoints, "<authentication>:"+string(egress.Authentication.Mode))
		}
		for _, port := range egress.ToPorts {
			for _, p := range port.Ports {
				proto := string(p.Protocol)
				if proto == "" {
					proto = "ANY"
				}
				peerPorts = append(peerPorts, helpers.Ports{
					Port:     p.Port,
					Protocol: proto,
				})
			}
		}
		rules = append(rules, helpers.RuleView{
			Endpoints: peerEndpoints,
			Ports:     peerPorts,
		})
	}

	for _, egressDeny := range egressesDeny {
		peerEndpoints := []string{}
		peerPorts := []helpers.Ports{}
		if egressDeny.ToCIDR != nil {
			peerEndpoints = append(peerEndpoints, egressDeny.ToCIDR.String())
		}
		for _, cidr := range egressDeny.ToCIDRSet {
			peerEndpoints = append(peerEndpoints, cidr.String())
		}
		for _, from := range egressDeny.ToEndpoints {
			var peerString string
			labelSel, err := ConvertEndpointSelectorToLabelSelector(from)
			if err != nil {
				fmt.Println("Error converting endpoint selector to label selector:", err)
				peerString += "<invalid endpoint selector>"
			} else {
				if namespace, ok := labelSel.MatchLabels["io.kubernetes.pod.namespace"]; ok {
					peerString += namespace + "/"
					delete(labelSel.MatchLabels, "io.kubernetes.pod.namespace")
				}
				peerString += metav1.FormatLabelSelector(labelSel)
			}
			peerEndpoints = append(peerEndpoints, peerString)
		}
		for _, entity := range egressDeny.ToEntities {
			peerEndpoints = append(peerEndpoints, "("+string(entity)+")")
		}
		for _, port := range egressDeny.ToPorts {
			for _, p := range port.Ports {
				proto := string(p.Protocol)
				if proto == "" {
					proto = "ANY"
				}
				peerPorts = append(peerPorts, helpers.Ports{
					Port:     p.Port,
					Protocol: proto,
				})
			}
		}
		peerEndpoints[0] = "<deny>" + peerEndpoints[0]
		rules = append(rules, helpers.RuleView{
			Endpoints: peerEndpoints,
			Ports:     peerPorts,
		})
	}
	return rules
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

func displayPolicies(policies []helpers.PolicyView) {
	cols := []helpers.Column{
		{Header: "KIND", Enable: getOptions.showKind},
		{Header: "NAMESPACE", Enable: getOptions.allNamespaces},
		{Header: "NAME", Enable: true},
		{Header: "POD-SELECTOR", Enable: true},
		{Header: "INGRESS", Enable: getOptions.showIngress},
		{Header: "INGRESS-PORTS", Enable: getOptions.showIngress},
		{Header: "EGRESS", Enable: getOptions.showEgress},
		{Header: "EGRESS-PORTS", Enable: getOptions.showEgress},
	}

	var activeCols []helpers.Column
	for _, c := range cols {
		if c.Enable {
			activeCols = append(activeCols, c)
		}
	}

	helpers.RenderTable(helpers.PoliciesToTableRows(policies, activeCols))
}
