# Kubernetes Authorization Audit with Slack Notifications

A complete Kubernetes solution that scans cluster users and service accounts, audits their permissions, and automatically sends formatted security reports to Slack.

![Status](https://img.shields.io/badge/status-ready-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📑 Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#-architecture)
- [Deployment Options](#-deployment-options)
- [Slack Setup](#-slack-app-setup)
- [What You'll Get](#-what-youll-get-in-slack)
- [Configuration](#-configuration)
- [Security](#-security)
- [Testing with Test Users](#-testing-with-test-users)
- [Troubleshooting](#-troubleshooting)
- [Cleanup](#-cleanup)

---

## 🚀 Quick Start

### Prerequisites

- Docker installed
- Minikube running (for Kubernetes)
- Slack app configured with bot token
- Docker Hub account (for public deployment)
- **OpenAI API key** (optional - for AI-powered risk analysis)

### Configuration Setup

The application uses a `config.yaml` file for configuration.

1. **Copy the example config:**
```bash
cp config.yaml.example config.yaml
```

2. **Edit `config.yaml` with your values:**
```yaml
slack:
  bot_token: "xoxb-your-actual-token"
  channel: "#kube-auth"

docker:
  username: "your-dockerhub-username"

openai:
  api_key: "sk-your-openai-key"  # Optional
  enabled: true
```

3. **Note:** `config.yaml` is in `.gitignore` and will NOT be committed

### Fastest Deployment

**1. Setup Configuration:**
```bash
# Create config file from example
make config

# Edit config.yaml with your secrets
# - slack.bot_token
# - docker.username  
# - openai.api_key (optional)
```

**2. Deploy:**
```bash
# Build and push to Docker Hub
make docker-login
make docker-build  # Uses docker.username from config.yaml

# Setup Kubernetes
make setup-minikube

# Deploy (uses secrets from config.yaml)
make helm-deploy
```

**3. Check Results:**
```bash
make logs
```

---

## ✨ Features

### 🔐 Authorization Auditing & Activity Detection
- Scans the last 10 active users and service accounts
- Analyzes RBAC permissions (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings)
- Identifies high-risk users with excessive permissions
- Detects cluster-admin and wildcard permissions
- Risk level assessment (HIGH/MEDIUM/LOW)
- **Activity Detection**: Tracks recent activities for users and service accounts
  - **Primary Method**: Attempts to use Kubernetes audit logs (if enabled and accessible)
  - **Fallback Method**: Uses Events API and recent resource changes when audit logs unavailable
  - **For Service Accounts**: 
    - Direct attribution via pods using the service account
    - Events in the service account's namespace
    - Recent deployments in the namespace
  - **For Regular Users**:
    - Events in namespaces where the user has RBAC bindings
    - Recent resource changes (pods, deployments) in those namespaces
    - Checks resource annotations for creator information when available
  - **Time Window**: Shows activities from the last 24 hours
  - **Activity Details**: Includes timestamps, resource types, actions, and status

### 🤖 AI-Powered Analysis (Optional)
- **OpenAI integration** for intelligent risk assessment
- Explains security risks and business impact
- Provides prioritized remediation recommendations
- Estimates fix time for each issue
- Identifies attack vectors and potential exploits

### 📊 Rich Reporting
- **Slack Messages**: Formatted reports with status, statistics, and recommendations
- **HTML Reports**: Interactive, downloadable reports with expandable details
- **Color-Coded Status**: 🔴 Critical, ⚠️ Warning, ✅ Healthy
- **Detailed Permissions**: Full breakdown of roles and permissions per user/SA

### 🔒 Security
- Non-privileged containers
- Read-only filesystem where possible
- Minimal RBAC permissions (only what's needed)
- Secrets excluded from Docker images
- Kubernetes Secrets for sensitive data

---

## 🏗️ Architecture

The application consists of two containers running in a Kubernetes Job:

1. **Auth Scanner Container**: 
   - Scans the cluster for users/service accounts and their permissions
   - Detects recent activities (audit logs → Events → resource changes)
   - Analyzes RBAC bindings and calculates risk levels
2. **Slack Notifier Container**: Monitors for scan results and sends formatted reports to Slack

```
┌─────────────────────────────────────────┐
│  Kubernetes Job                         │
│  ┌───────────────────────────────────┐  │
│  │  Auth Scanner Container           │  │
│  │  - Scans users/service accounts   │  │
│  │  - Analyzes RBAC permissions      │  │
│  │  - Writes results to shared vol   │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Slack Notifier Container         │  │
│  │  - Monitors shared volume         │  │
│  │  - Generates HTML report          │  │
│  │  - Sends to Slack                 │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Shared Volume (emptyDir)         │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

---

## 📦 Deployment Options

### Option 1: Helm (Recommended)

**One-time Job:**
```bash
make helm-deploy
```

**Scheduled CronJob:**
```bash
make helm-deploy-cron
# Or with custom schedule:
make helm-deploy-cron CRON_SCHEDULE="0 */6 * * *"  # Every 6 hours
```

### Option 2: kubectl/kustomize

**One-time Job:**
```bash
make deploy
```

**Scheduled CronJob:**
```bash
make deploy-cron
```

---

## 🔧 Slack App Setup

### Step 1: Create Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **"Create an App"** → **"From scratch"**
3. Name: `kube-auth-auditor`
4. Choose your workspace
5. Click **"Create App"**

### Step 2: Configure Bot Permissions

1. Go to **Features → OAuth & Permissions**
2. Scroll to **"Bot Token Scopes"** and add:
   ```
   - app_mentions:read
   - channels:join
   - channels:read       ← Required for file uploads!
   - chat:write
   - files:write
   ```
3. Click **"Install to Workspace"**
4. **Copy the Bot User OAuth Token** (starts with `xoxb-`)

### Step 3: Add Bot to Channel

```bash
# In your Slack channel (e.g., #kube-auth)
/invite @kube-auth-auditor
```

### Step 4: Test

```bash
export SLACK_BOT_TOKEN=xoxb-your-token-here
make test
```

✅ **You should see test messages in your Slack channel!**

**Note:** `make test` will:
- Create test users and service accounts
- Scan the cluster and send reports to Slack
- Automatically clean up test resources when done

---

## 📊 What You'll Get in Slack

### 1. 📱 Formatted Slack Message

A rich message with:
- **Overall Status**: ✅ HEALTHY / ⚠️ WARNING / 🔴 CRITICAL
- **Summary Statistics**: Total users, service accounts, high privilege users
- **Critical Risks**: High-risk users highlighted
- **User Breakdown**: Status for each user/service account
- **Recommendations**: Actionable security improvements
- **AI Analysis**: (if enabled) Detailed risk assessment

### 2. 🎨 Interactive HTML Report

A beautiful, downloadable HTML file with:
- **Executive Summary**: Visual dashboard with color-coded stats
- **User Details**: Every user/SA with full permission breakdown
- **Recent Activities**: Shows recent actions (pods created, events, deployments)
  - For service accounts: Direct attribution via `serviceAccountName`
  - For users: Activity in namespaces where they have permissions
  - Timestamps and resource details for each activity
- **Expandable Sections**: Click to expand/collapse user details
- **Risk Factors**: Highlighted security concerns
- **AI-Powered Insights**: Explains risks and remediation (when enabled)
- **Color Coding**: ✅ Low risk (green), ⚠️ Medium (yellow), 🔴 High (red)
- **Mobile Responsive**: Works on any device
- **Print Friendly**: Ready for PDF export

---

## ⚙️ Configuration

### Primary Method: config.yaml (Recommended)

1. **Create config file:**
```bash
make config  # Creates config.yaml from config.yaml.example
```

2. **Edit config.yaml:**
```yaml
slack:
  bot_token: "xoxb-your-token-here"
  channel: "#kube-auth"

docker:
  username: "your-dockerhub-username"

openai:
  api_key: "sk-your-key"  # Optional
  enabled: true
```

3. **Benefits:**
- All secrets in one file
- Version control excluded (`.gitignore`)
- Easy to manage

### Alternative: Environment Variables

You can still use environment variables (they work as fallback):
| Variable | Default | Description |
|----------|---------|-------------|
| `SLACK_BOT_TOKEN` | Required | Bot OAuth token |
| `SLACK_CHANNEL` | `#kube-auth` | Target channel |
| `OPENAI_API_KEY` | Optional | For AI-powered security analysis |
| `MAX_USERS` | `10` | Maximum users/service accounts to scan |

### 🤖 AI Analysis Configuration

**Enable AI analysis:**

```bash
# Set OpenAI API key
export OPENAI_API_KEY="sk-..."

# Or set via Kubernetes secret
make openai-secret OPENAI_API_KEY=sk-your-key

# Or add to Kubernetes secret
kubectl create secret generic openai-credentials \
  --from-literal=openai-api-key="sk-..." \
  --namespace kube-auth
```

**AI analysis provides:**
- ✅ Overall risk assessment with color-coded severity badges
- 🎯 Top 3-5 critical security concerns with business impact
- 💡 **WHY IT'S DANGEROUS** - Attack vectors and potential exploits
- 🔍 **EXPLANATION** - What attackers could do with these permissions
- 📋 Prioritized remediation roadmap with time estimates
- ⚠️ Specific risks for each high-risk entity

**Disable AI analysis:**
- Simply omit the `OPENAI_API_KEY` environment variable
- The system will skip AI analysis gracefully
- All other features continue to work normally

---

## 🔐 Security

This application requires RBAC read permissions to audit cluster authorization. The following security measures are implemented:

### Security Measures

#### 1. Non-Privileged Container

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

**Benefits:**
- Container runs as non-root user (UID 1000)
- No privilege escalation allowed
- All Linux capabilities dropped
- Follows principle of least privilege

#### 2. Minimal RBAC Permissions

The scanner requires read permissions for auditing:
- `serviceaccounts`, `pods`, `secrets`, `namespaces`, `events`: `get`, `list`
- `deployments`, `replicasets` (from `apps` API group): `get`, `list`
- `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`: `get`, `list`
- `create`, `delete` permissions (only for test mode - creating test users/SAs)

**Benefits:**
- No write permissions in production mode
- Cannot modify cluster state
- Read-only access to authorization data and activity logs
- Test mode allows creating temporary test resources for validation

#### 3. Secrets Management

- Secrets excluded from Docker image via `.dockerignore`
- Kubernetes Secrets for Slack token and OpenAI API key
- Environment variable injection at runtime
- `config.yaml` excluded from Git (`.gitignore`)

### Best Practices

1. **Restrict to Specific Namespaces** (Optional)
   ```yaml
   nodeSelector:
     kubernetes.io/os: linux
   ```

2. **Use Network Policies** (Optional)
   - Restrict egress to Slack and OpenAI APIs only

3. **Regular Audits**
   - Review RBAC permissions regularly
   - Rotate secrets periodically
   - Monitor for unauthorized access

---

## 🐛 Troubleshooting

### Common Issues

**1. "channel_not_found" error**
```bash
# Invite bot to channel
/invite @kube-auth-auditor

# Verify token
curl -H "Authorization: Bearer xoxb-your-token" \
  https://slack.com/api/auth.test
```

**2. "missing_scope" error**
- Add required scopes in OAuth & Permissions
- Reinstall the app after adding scopes

**3. Job fails to start**
```bash
# Check minikube
minikube status
minikube start

# Verify image
minikube image ls | grep kube-auth-manager

# Load image if missing
make build
```

**4. No notifications in Slack**
```bash
# Check notifier logs
kubectl logs job/kube-auth-health-check -n kube-auth -c slack-notifier

# Verify secret
kubectl get secret slack-credentials -n kube-auth -o yaml

# Test token
make test
```

**5. No users/service accounts found**
```bash
# Verify RBAC permissions
kubectl auth can-i list serviceaccounts --as=system:serviceaccount:kube-auth:kube-auth-sa -n kube-auth

# Check scanner logs
kubectl logs job/kube-auth-health-check -n kube-auth -c auth-scanner
```

**6. No activity detected for users/service accounts**
```bash
# Activity detection uses:
# 1. Audit logs (if enabled) - requires cluster-admin and audit logging enabled
# 2. Events API - shows events in namespaces
# 3. Resource changes - shows recent pods/deployments

# Check if audit logs are enabled
kubectl get apiserverconfigs.auditregistration.k8s.io

# Verify events are accessible
kubectl get events --all-namespaces

# For service accounts, activity is detected via pods using that SA
# For users, activity is shown in namespaces where they have bindings
```

### Debug Commands

```bash
# View all resources
kubectl get all -n kube-auth

# Describe job
kubectl describe job kube-auth-health-check -n kube-auth

# Check secret
kubectl get secret slack-credentials -n kube-auth

# Test Slack locally
export SLACK_BOT_TOKEN=xoxb-your-token
make test
```

---

## 🧪 Testing with Test Users

### Create Test Users for Deployment Testing

If you want to test your deployment with test users and service accounts:

```bash
# Create test users and service accounts (no Slack reports, no cleanup)
make users-create
```

This will create:
- Test namespace: `auth-test`
- Test users: `test-admin-user`, `test-reader-user`
- Test service accounts: `test-admin-sa`, `test-reader-sa`, `test-writer-sa`
- Test roles and bindings with different permission levels

**Then deploy and test:**
```bash
make build
make helm-deploy
```

The deployed job will detect and scan these test users.

### Clean Up Test Users

```bash
# Clean up test users and service accounts
make users-clean
```

This removes all test resources including the `auth-test` namespace.

### Full Test (with Slack Reports)

```bash
# Full test: creates users, sends Slack reports, then cleans up
make test
```

This is useful for testing the complete workflow including Slack integration.

---

## 🧹 Cleanup

### Remove Deployment Resources

```bash
# Kubernetes deployment
make clean

# Helm deployment
make helm-clean

# Both
make clean && make helm-clean
```

### Remove Test Users

```bash
# Clean up test users and service accounts
make users-clean
```

### Complete Cleanup

```bash
# Remove all resources
make clean
make helm-clean

# Remove test users
make users-clean

# Remove Docker images
docker rmi kube-auth-manager:latest

# Remove namespace
kubectl delete namespace kube-auth
```

---

## 📚 Project Structure

```
├── src/                          # Source code
│   ├── slack_app/                # Slack integration
│   │   ├── client.py            # Slack API client
│   │   ├── formatter.py         # Message formatting
│   │   └── notifier.py          # Notification logic
│   ├── auth_analyzer/           # Authorization analysis
│   │   ├── scanner.py           # Auth scanning
│   │   └── analyzer.py           # Result analysis
│   ├── utils/                    # Utilities
│   │   ├── html_report.py       # HTML report generation
│   │   ├── config.py             # Configuration
│   │   └── logger.py          # Logging setup
│   ├── app.py                   # Main application
│   ├── main.py                  # Entry point
│   ├── requirements.txt         # Python dependencies
│   └── Dockerfile               # Container image
├── k8s/                          # Kubernetes manifests
│   ├── namespace.yaml            # Namespace definition
│   ├── rbac.yaml                # RBAC configuration
│   ├── kube-auth-job.yaml       # Job definition
│   ├── kube-auth-cronjob.yaml   # CronJob definition
│   └── kustomization.yaml       # Kustomize config
├── helm/                         # Helm chart
│   └── kube-auth-manager/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
├── scripts/                      # Deployment scripts
├── Makefile                      # Project commands
└── README.md                     # This file
```

---

## 🛠️ Available Commands

See `make help` for all available commands, or check the Makefile.

**Key commands:**
- `make config` - Create config.yaml from example
- `make install` - Install Python dependencies
- `make test` - Test Slack connection locally (creates test users, sends reports, cleans up)
- `make users-create` - Create test users and service accounts (no Slack, no cleanup)
- `make users-clean` - Clean up test users and service accounts
- `make build` - Build Docker image
- `make docker-build` - Build and push to Docker Hub
- `make helm-deploy` - Deploy using Helm
- `make logs` - View application logs
- `make status` - Check deployment status
- `make clean` - Clean up resources

---

## 📄 License

MIT License - See LICENSE file for details.

---

**Need help?** Check the [Troubleshooting](#-troubleshooting) section or open an issue on GitHub.

