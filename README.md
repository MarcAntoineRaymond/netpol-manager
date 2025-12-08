![GitHub Release](https://img.shields.io/github/v/release/MarcAntoineRaymond/netpol-manager?filter=*)

[![Go Report Card](https://goreportcard.com/badge/github.com/MarcAntoineRaymond/netpol-manager)](https://goreportcard.com/report/github.com/MarcAntoineRaymond/netpol-manager)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MarcAntoineRaymond/netpol-manager/badge)](https://scorecard.dev/viewer/?uri=github.com/MarcAntoineRaymond/netpol-manager)
[![Go lint, test and gosec](https://github.com/MarcAntoineRaymond/netpol-manager/actions/workflows/go.yaml/badge.svg)](https://github.com/MarcAntoineRaymond/netpol-manager/actions/workflows/go.yaml)

Netpol-manager is tool to list Kubernetes and Cilium Network policy and filter them based on which pods they apply to.

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
kubectl netpol get -p app.kubernetes.io/name=test -A
Kind                  Namespace        Name                     Pod-Selector                  Ingress   Egress
CiliumNetworkPolicy   authentication   untitled-policy-cilium   app.kubernetes.io/name=test   <=X       =>kube-system/app=back : 443/UDP, 8080/TCP
                                                                                                        =>app=front : 420, 80/TCP
CiliumNetworkPolicy   authentication   untitled-policy-cilium   app.kubernetes.io/name=test   <=X       =>kube-system/app=back : 443/UDP, 8080/TCP
                                                                                                        =>app=front : 420, 80/TCP
```
