#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# launch-ec2.sh — provision the IAM role + security group, then launch the
# instance. Run this from your own machine with AWS CLI configured (this is
# a one-time setup step — it is NOT something to run on the EC2 box itself).
#
# What this deliberately does NOT do:
#   - Open any inbound port except SSH, and only from YOUR_IP/32.
#     If you later run Dependency-Track's UI on this box, do not open its
#     port here — reach it via `ssh -L 8080:localhost:8080 ...` instead. See
#     the README's original Dependency-Track section for why: it's a map of
#     every vulnerable thing you run, and shouldn't be internet-facing.
#   - Put any AWS credential on the box. Auth to Bedrock happens entirely
#     through the instance role this script creates — no keys to leak.
#
# Usage:
#   export YOUR_IP=$(curl -s https://checkip.amazonaws.com)/32
#   ./launch-ec2.sh
#
# Adjust INSTANCE_TYPE / VOLUME_SIZE_GB below for your workload — the
# defaults assume occasional fuzzing campaigns, not a permanently-running
# Dependency-Track instance alongside them (bump both if you want both
# running concurrently).
# ---------------------------------------------------------------------------
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m6i.xlarge}"     # 4 vCPU / 16 GiB — see note above
VOLUME_SIZE_GB="${VOLUME_SIZE_GB:-50}"           # default AL2023 root volume is 8 GiB; Docker images + vuln DBs + corpora eat that fast
KEY_NAME="${KEY_NAME:?Set KEY_NAME to an existing EC2 key pair name}"
YOUR_IP="${YOUR_IP:?Set YOUR_IP to your-ip/32, e.g. export YOUR_IP=\$(curl -s https://checkip.amazonaws.com)/32}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLE_NAME="sbom-toolkit-bedrock-role"
PROFILE_NAME="sbom-toolkit-bedrock-profile"
POLICY_NAME="sbom-toolkit-bedrock-policy"
SG_NAME="sbom-toolkit-sg"

echo "=== Region: $REGION | Instance type: $INSTANCE_TYPE | Your IP: $YOUR_IP ==="

echo; echo "[1/5] IAM role for Bedrock access..."
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$HERE/iam-trust-policy.json" >/dev/null
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" \
    --policy-document "file://$HERE/iam-bedrock-policy.json"
  echo "  Created role $ROLE_NAME."
else
  echo "  Role $ROLE_NAME already exists — reusing it."
fi

if ! aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" --role-name "$ROLE_NAME"
  echo "  Created instance profile $PROFILE_NAME."
  echo "  Waiting ~15s for IAM propagation before launch can reference it..."
  sleep 15
else
  echo "  Instance profile $PROFILE_NAME already exists — reusing it."
fi

echo; echo "[2/5] Security group (SSH from $YOUR_IP only, nothing else inbound)..."
VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text --region "$REGION")
if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
  echo "[!] No default VPC found in $REGION. Either create one (aws ec2 create-default-vpc" \
       "--region $REGION) or set VPC_ID yourself and adapt this script — it assumes a default VPC exists."
  exit 1
fi
SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null || echo "None")
if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  SG_ID=$(aws ec2 create-security-group --group-name "$SG_NAME" \
    --description "SBOM security toolkit - SSH only" --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text --region "$REGION")
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "$YOUR_IP" --region "$REGION" >/dev/null
  echo "  Created $SG_ID, SSH open to $YOUR_IP only."
else
  echo "  Security group $SG_NAME already exists ($SG_ID) — reusing it."
fi

echo; echo "[3/5] Looking up the current Amazon Linux 2023 AMI via SSM (not a hardcoded ID)..."
AMI_ID=$(aws ssm get-parameters \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text --region "$REGION")
echo "  Using $AMI_ID"
ROOT_DEVICE=$(aws ec2 describe-images --image-ids "$AMI_ID" \
  --query 'Images[0].RootDeviceName' --output text --region "$REGION")

echo; echo "[4/5] Launching the instance..."
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --iam-instance-profile "Name=$PROFILE_NAME" \
  --block-device-mappings "[{\"DeviceName\":\"${ROOT_DEVICE}\",\"Ebs\":{\"VolumeSize\":${VOLUME_SIZE_GB},\"VolumeType\":\"gp3\"}}]" \
  --user-data "file://$HERE/bootstrap.sh" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=sbom-security-toolkit}]' \
  --query 'Instances[0].InstanceId' --output text --region "$REGION")
echo "  Launched $INSTANCE_ID — bootstrap.sh will run automatically as user-data."

echo; echo "[5/5] Waiting for it to reach 'running'..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text --region "$REGION")

cat <<EOF

=================================================================
[✓] Instance running: $INSTANCE_ID at $PUBLIC_IP

Bootstrap runs as user-data on first boot — give it 3-5 minutes, then:
  ssh -i /path/to/${KEY_NAME}.pem ec2-user@${PUBLIC_IP}

Check bootstrap finished (it logs to cloud-init's own log):
  ssh -i /path/to/${KEY_NAME}.pem ec2-user@${PUBLIC_IP} \\
    'sudo tail -50 /var/log/cloud-init-output.log'

Then pull the toolkit onto the box and set the Bedrock env vars —
see bootstrap.sh's final printed instructions, or the README's
EC2/Bedrock section.
=================================================================
EOF
