![GitHub Release](https://img.shields.io/github/v/release/MarcAntoineRaymond/netpol-manager?filter=*)

[![Go Report Card](https://goreportcard.com/badge/github.com/MarcAntoineRaymond/netpol-manager)](https://goreportcard.com/report/github.com/MarcAntoineRaymond/netpol-manager)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MarcAntoineRaymond/netpol-manager/badge)](https://scorecard.dev/viewer/?uri=github.com/MarcAntoineRaymond/netpol-manager)
[![Go lint, test and gosec](https://github.com/MarcAntoineRaymond/netpol-manager/actions/workflows/go.yaml/badge.svg)](https://github.com/MarcAntoineRaymond/netpol-manager/actions/workflows/go.yaml)

Netpol-manager is tool to list Kubernetes Network policy and filter them based on which pods they apply to.

This tool support Cilium network policy and aggregate the different policies kinds in one output. Kinds can be filtered out using `-k`.

It can be used as a kubectl plugin.

# Getting Started 🚀

Download and copy binary in your PATH:

```sh
mv kubectl-netpol /usr/local/bin/
```

Run kubectl using the new command:

```sh
kubectl netpol --help
kubectl netpol get -A
```

Sample with testpolicies:
```sh
# Show all networkpolicies in all namespaces of all kinds (classic network policies and cilium kinds) that apply to pods with label app.kubernetes.io/name=test
kubectl netpol get -A -p app.kubernetes.io/name=test --show-kind
┌────────────────────────────────┬────────────────┬───────────────────────────────┬─────────────────────────────┬────────────────────────┬───────────────┬────────────────────────┬──────────────┐
│              KIND              │   NAMESPACE    │             NAME              │        POD-SELECTOR         │        INGRESS         │ INGRESS-PORTS │         EGRESS         │ EGRESS-PORTS │
├────────────────────────────────┼────────────────┼───────────────────────────────┼─────────────────────────────┼────────────────────────┼───────────────┼────────────────────────┼──────────────┤
│ CiliumNetworkPolicy            │ authentication │ untitled-policy-cilium        │ <none>                      │ kube-system/app=back   │ UDP/443       │ kube-system/app=back   │ UDP/443      │
│                                │                │                               │                             │ security/app=test      │ TCP/8080      │ security/app=test      │ ANY/8080     │
│                                │                │                               │                             │ cert-manager/app=front │               │ cert-manager/app=front │              │
│                                │                │                               │                             ├────────────────────────┼───────────────┼────────────────────────┼──────────────┤
│                                │                │                               │                             │                        │               │ app=front              │ ANY/420      │
│                                │                │                               │                             │                        │               │                        │ TCP/80       │
├────────────────────────────────┼────────────────┼───────────────────────────────┼─────────────────────────────┼────────────────────────┼───────────────┼────────────────────────┼──────────────┤
│ CiliumClusterwideNetworkPolicy │ *              │ untitled-clusterpolicy-cilium │ app.kubernetes.io/name=test │ <defaultdeny>          │               │ kube-system/app=back   │ UDP/443      │
│                                │                │                               │                             │                        │               │                        │ TCP/8080     │
│                                │                │                               │                             ├────────────────────────┼───────────────┼────────────────────────┼──────────────┤
│                                │                │                               │                             │                        │               │ app=front              │ ANY/420      │
│                                │                │                               │                             │                        │               │                        │ TCP/80       │
└────────────────────────────────┴────────────────┴───────────────────────────────┴─────────────────────────────┴────────────────────────┴───────────────┴────────────────────────┴──────────────┘
```
