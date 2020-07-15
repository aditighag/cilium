.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _host_firewall:

********************
Host Firewall (beta)
********************

This document serves as an introduction to Cilium's host firewall, to enforce
security policies for Kubernetes nodes.

.. include:: ../beta.rst

Enable the Host Firewall in Cilium
==================================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal ::

    helm install cilium |CHART_RELEASE|        \\
      --namespace kube-system                  \\
      --set global.kubeProxyReplacement=strict \\
      --set global.hostFirewall=true           \\
      --set global.devices=ethX,ethY

At this point, the Cilium-managed nodes are ready to enforce network policies.


Enable Policy Audit Mode for the Host Endpoint
==============================================

When applying `HostPolicies` carelessly, it's easy to block the access to the
nodes or to break the cluster's normal behavior (ex. by blocking communication
with kube-api).

To avoid such issues, we can switch the host firewall in audit mode, to
validate the impact of host policies before enforcing them.

::

    $ HOST_EP_ID=$(cilium endpoint list -o json | jq '.[] | select( .status.identity.id == 1 ).id')
    $ cilium endpoint config $HOST_EP_ID PolicyAuditMode=Enabled
    Endpoint 3353 configuration updated successfully
    $ cilium endpoint config $HOST_EP_ID | grep PolicyAuditMode
    PolicyAuditMode          Enabled


Apply a Host Network Policy
===========================

`HostPolicies` match on node labels using a :ref:`NodeSelector` to identify the
nodes to which the policy applies. The following policy applies to all nodes.
It allows communications from outside the cluster only on port TCP/22. All
communications from the cluster to the hosts are allowed.

Host policies don't apply to communications between pods or between pods and
the outside of the cluster, except if those pods are host-networking pods.

.. literalinclude:: ../../examples/policies/host/demo-host-policy.yaml

To apply this policy, run:

.. parsed-literal ::

    $ kubectl create -f \ |SCM_WEB|\/examples/policies/host/demo-host-policy.yaml
    ciliumclusterwidenetworkpolicy.cilium.io/demo-host-policy created

The host is represented as a special endpoint, with label ``reserved:host``, in
the output of command ``cilium endpoint list``. You can therefore inspect the
status of the policy using that command.

.. parsed-literal ::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Disabled (Audit)   Disabled          1          reserved:host                                                                         ready
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready


Adjust the Host Policy to Your Environment
==========================================

As long as the host endpoint is running in audit mode, communications
disallowed by the policy won't be dropped. They will however be reported by
``cilium monitor`` as ``action audit``. The audit mode thus allows you to
adjust the host policy to your environment, to avoid unexpected connection
breakages.

.. parsed-literal ::

    $ cilium monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 1, ingress, action allow, match L3-Only, 192.168.33.12 -> 192.168.33.11 EchoRequest
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 6, proto 6, ingress, action allow, match L3-Only, 192.168.33.12:37278 -> 192.168.33.11:2379 tcp SYN
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action audit, match none, 10.0.2.2:47500 -> 10.0.2.15:6443 tcp SYN

.. warning::

    Make sure that none of the communications required to access the cluster or
    for the cluster to work properly are denied. They should appear as ``action
    allow``.



Disable Policy Audit Mode
=========================

Once you are confident all required communication to the host from outside the
cluster are allowed, you can disable policy audit mode to enforce the host
policy.

.. parsed-literal ::

    $ cilium endpoint config $HOST_EP_ID PolicyAuditMode=Disabled
    Endpoint 3353 configuration updated successfully

Ingress host policies should now appear as enforced:

.. parsed-literal ::

    $ cilium endpoint list
    ENDPOINT   POLICY (ingress)   POLICY (egress)   IDENTITY   LABELS (source:key[=value])                       IPv6                 IPv4           STATUS
               ENFORCEMENT        ENFORCEMENT
    266        Disabled           Disabled          104        k8s:io.cilium.k8s.policy.cluster=default          f00d::a0b:0:0:ef4e   10.16.172.63   ready
                                                               k8s:io.cilium.k8s.policy.serviceaccount=coredns
                                                               k8s:io.kubernetes.pod.namespace=kube-system
                                                               k8s:k8s-app=kube-dns
    1687       Enabled            Disabled          1          reserved:host                                                                         ready
    3362       Disabled           Disabled          4          reserved:health                                   f00d::a0b:0:0:49cf   10.16.87.66    ready


Communications not explicitly allowed by the host policy will now be dropped:

.. parsed-literal ::

    $ cilium monitor -t policy-verdict --related-to $HOST_EP_ID
    Policy verdict log: flow 0x0 local EP ID 1687, remote ID 2, proto 6, ingress, action deny, match none, 10.0.2.2:49038 -> 10.0.2.15:21 tcp SYN


Clean-up
========

.. parsed-literal ::

   $ kubectl delete ccnp demo-host-policy
