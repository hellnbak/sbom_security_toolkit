# AWS Bedrock Configuration Troubleshooting

This guide helps resolve common AWS Bedrock configuration issues.

## Quick Fix

If you're seeing model ID errors, the toolkit now handles this automatically. Just ensure:

```bash
export CLAUDE_BACKEND=bedrock
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
```

Then run normally - no `CLAUDE_MODEL` variable needed.

## Common Issues

### Issue 1: Invalid Model ID (400 Error)

**Error:**
```
anthropic.BadRequestError: Error code: 400 - Invocation of model ID 
anthropic.claude-sonnet-5 with on-demand throughput isn't supported
```

**Cause:** Using an older version before the fix was applied.

**Solution:**
```bash
# Verify you have the latest version
grep "claude-3-5-sonnet-20241022" vuln-scan/call_claude.py

# Should show the backend-aware defaults
# If not, pull latest version:
git pull origin main
```

### Issue 2: Permission Errors (403)

**Error:**
```
Error code: 403 - Permission Error: not authorized to perform 
bedrock-mantle:CreateInference
```

**Cause:** IAM role missing required permissions.

**Solution:**
```bash
# Verify IAM policy is attached
aws iam get-role-policy \
  --role-name sbom-toolkit-bedrock-role \
  --policy-name sbom-toolkit-bedrock-policy

# If missing, apply the policy
aws iam put-role-policy \
  --role-name sbom-toolkit-bedrock-role \
  --policy-name sbom-toolkit-bedrock-policy \
  --policy-document file://aws/iam-bedrock-policy.json
```

### Issue 3: Model Not Available

**Error:**
```
Model not found or not accessible in this region
```

**Cause:** Model not enabled in Bedrock console, or wrong region.

**Solution:**
1. Go to AWS Console → Bedrock → Model access
2. Enable "Claude 3.5 Sonnet"
3. Wait for access to be granted (usually instant)
4. Verify region: `us-east-1`, `us-west-2`, `eu-west-1` all have Claude 3.5

### Issue 4: Claude CLI Fails

**Error:**
```
[call_claude.py] claude -p failed (exit 1): Input must be provided...
```

**Status:** Non-blocking - this is handled by automatic fallback.

**Explanation:** The script tries Claude CLI first, then falls back to SDK.
This warning is informational - as long as the final result works, you can ignore it.

## Verification

Test your configuration:

```bash
# Basic test
python3 vuln-scan/call_claude.py \
  --backend bedrock \
  --prompt "Say: configuration working"

# Expected output: "configuration working"
```

## Valid Model IDs

If you need to override the default:

```bash
# Latest Claude 3.5 Sonnet (Default)
export CLAUDE_MODEL="claude-3-5-sonnet-20241022-v2:0"

# Claude 3 Opus (Most capable)
export CLAUDE_MODEL="claude-3-opus-20240229-v1:0"

# Claude 3 Haiku (Fastest)
export CLAUDE_MODEL="claude-3-haiku-20240307-v1:0"
```

## Support

For more details, see:
- `docs/guides/aws-bedrock-deployment.md` - Full setup guide
- `CONTRIBUTING.md` - How to report issues
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
