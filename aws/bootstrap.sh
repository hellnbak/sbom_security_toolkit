#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# bootstrap.sh — set up an Amazon Linux 2023 EC2 instance to run this toolkit.
#
# Targets AL2023 specifically, not Amazon Linux 2 — AL2 reaches end-of-
# support on 2026-06-30, so launching anything new on it starting now means
# starting on an OS that's already outside the security-update window.
# AL2023 uses dnf (yum is kept as an alias, but this uses dnf directly since
# AL2023 also drops the amazon-linux-extras mechanism AL2 needed for things
# like Docker — different enough underneath that "just use yum like before"
# isn't a safe assumption to carry over).
#
# Run this as the EC2 instance's user-data (pasted at launch — see
# launch-ec2.sh), or manually via SSH: sudo bash bootstrap.sh
#
# What it does NOT do: fetch this toolkit's own files onto the box. Pull
# those separately (git clone your fork/mirror of it, or scp the zip) after
# this finishes — bootstrap.sh only prepares the environment.
# ---------------------------------------------------------------------------
set -euo pipefail

echo "=== Updating system packages ==="
dnf update -y

echo "=== Installing base tooling ==="
dnf install -y git jq python3 python3-pip unzip tar gzip

echo "=== Installing Docker ==="
dnf install -y docker
systemctl enable --now docker
usermod -aG docker ec2-user || true   # picks up on next login/SSH session

echo "=== Installing Node.js (for Claude Code) ==="
# AL2023's own nodejs package is often several versions behind; NodeSource's
# setup script is the more reliable way to get a current LTS release.
curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -
dnf install -y nodejs

echo "=== Installing Claude Code ==="
npm install -g @anthropic-ai/claude-code

echo "=== Installing OSV-Scanner (pinned, latest release binary) ==="
curl -fsSL -o /usr/local/bin/osv-scanner \
  "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64"
chmod +x /usr/local/bin/osv-scanner

echo "=== Installing Trivy (pinned + checksum-verified — see note below) ==="
# Same rationale as ci/github-actions-vuln-scan.yml: install the verified
# binary directly rather than a GitHub Action wrapper, and pin a specific
# version rather than tracking "latest" for a security tool. Bump this
# deliberately after checking release notes, same as in the CI file.
TRIVY_VERSION="0.72.0"
TRIVY_TARBALL="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
cd /tmp
# IMPORTANT: keep the local filename identical to what Trivy's own
# checksums.txt lists — sha256sum -c looks up the file by the exact name
# in that file. Saving the download under any other name (e.g. trivy.tar.gz)
# makes verification fail with "No such file or directory" even though the
# download itself succeeded, which silently halts this whole script under
# set -e before anything after it (including this SDK install below) runs.
curl -fsSL -o "$TRIVY_TARBALL" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_TARBALL}"
curl -fsSL -o checksums.txt \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
grep "${TRIVY_TARBALL}\$" checksums.txt | sha256sum -c -
tar xzf "$TRIVY_TARBALL" trivy
mv trivy /usr/local/bin/trivy
rm -f "$TRIVY_TARBALL" checksums.txt

echo "=== Installing the anthropic Python SDK (direct API + Bedrock support) ==="
# Try without the flag first: --break-system-packages was pip 23+ (PEP 668).
# AL2023's default python3.9 ships pip 21.3.1, which doesn't recognize the
# flag AT ALL and errors with "no such option" — it needs the plain form.
# Newer pip on a PEP-668-managed system needs the flag instead, hence the
# fallback rather than picking one and assuming it's right everywhere.
python3 -m pip install "anthropic[bedrock]" || \
  python3 -m pip install "anthropic[bedrock]" --break-system-packages

echo "=== Confirming AWS CLI is present (ships on the standard AL2023 AMI) ==="
if ! command -v aws >/dev/null 2>&1; then
  echo "  Not found — installing AWS CLI v2 manually."
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  ( cd /tmp && unzip -q awscliv2.zip && ./aws/install )
fi

echo
echo "=== Versions ==="
docker --version
node --version
claude --version || true
osv-scanner --version || true
trivy --version
python3 -c "import anthropic; print('anthropic sdk', anthropic.__version__)"
aws --version

cat <<'EOF'

=================================================================
Bootstrap complete. Still needed before running anything:

1. Log out and back in (or `newgrp docker`) so the docker group
   membership takes effect for interactive commands.

2. Pull the toolkit itself onto this box — this script doesn't
   fetch it. E.g.:
     git clone <your fork/mirror of the toolkit> sbom-security-toolkit
   or scp the zip up and unzip it.

3. Set the Bedrock env vars (see ../README.md's EC2/Bedrock
   section for the full explanation of each):
     export CLAUDE_BACKEND=bedrock
     export CLAUDE_CODE_USE_BEDROCK=1
     export AWS_REGION=us-east-1   # wherever your model access is granted

4. Confirm the instance role actually has Bedrock access. Note this
   tests InvokeModel directly, NOT `aws bedrock list-foundation-models`
   — that needs bedrock:ListFoundationModels, which the IAM policy in
   ../aws/iam-bedrock-policy.json deliberately does not grant (least
   privilege: only what's actually needed to call a model, nothing to
   browse the catalog with):
     aws sts get-caller-identity
     python3 vuln-scan/call_claude.py --backend bedrock --prompt "Say OK"
   If get-caller-identity shows the assumed role but the second command
   errors with AccessDenied on bedrock-mantle:CreateInference, this
   role's policy predates that statement being added — Claude Sonnet 5
   goes through a Mantle endpoint that needs its own IAM namespace
   (bedrock-mantle:*), entirely separate from classic bedrock:InvokeModel.
   Re-apply the current iam-bedrock-policy.json to the existing role
   from your own machine (not the EC2 box):
     aws iam put-role-policy --role-name sbom-toolkit-bedrock-role \
       --policy-name sbom-toolkit-bedrock-policy \
       --policy-document file://iam-bedrock-policy.json
   If instead it errors about model access, that's Step 1 in the
   README (Bedrock console > Model access) not being granted yet.
=================================================================
EOF
