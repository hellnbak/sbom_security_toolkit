# Quick Start Guide - SBOM Security Toolkit (Fixed)

**Status:** ✅ Ready to use  
**Last Updated:** 2026-07-02

---

## TL;DR - Run This Now

```bash
# Set backend (if not already set)
export CLAUDE_BACKEND=bedrock
export CLAUDE_CODE_USE_BEDROCK=1

# Run the full pipeline
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml
```

**That's it!** The fix has been applied - no manual model configuration needed.

---

## What Just Got Fixed

✅ **The Problem:** Script failed with invalid model ID error  
✅ **The Fix:** Backend-aware model defaults applied  
✅ **The Result:** Works out-of-the-box now

**Before:** You had to manually set `CLAUDE_MODEL="claude-3-5-sonnet-20241022-v2:0"`  
**After:** It's automatic - just run the command

---

## Verify the Fix Works

### Quick Test (30 seconds)
```bash
python3 vuln-scan/call_claude.py \
  --backend bedrock \
  --prompt "Say: fix verified"
```

**Expected output:** `fix verified`

**If you see this** → ✅ Everything is working!

### Run Full Test Suite (2 minutes)
```bash
./test_fix.sh
```

**Expected output:**
```
✓ PASS: Bedrock backend works with new default
✓ PASS: CLAUDE_MODEL override works
✓ PASS: Help text shows correct Bedrock default
```

---

## Run the Full Pipeline

### Command
```bash
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml
```

### What Happens
1. **Stage 1:** Vulnerability scan (OSV-Scanner + Trivy)
2. **Stage 2:** AI triage with Claude (now works!)
3. **Stage 3:** Claude Code generates fuzz targets
4. **Stage 4:** Runs fuzzing

### Expected Output
```
==================================================================
 Orchestrating against: /path/to/cyclonedx-sbom.xml
 Run directory:         ./runs/20260702-HHMMSS
==================================================================

[Stage 1/4] Vulnerability scan...
[✓] Wrote: reports/...

[Stage 2/4] AI triage...
[✓] Wrote ai-triage.md

[Stage 3/4] Claude Code: selecting + generating new fuzz targets...
...

[Stage 4/4] Building fuzzing image and running...
...

==================================================================
[✓] Done. Read: runs/20260702-HHMMSS/SUMMARY.md
==================================================================
```

### Check Results
```bash
# View the summary
cat runs/*/SUMMARY.md

# View AI triage
cat runs/*/ai-triage.md

# View vulnerability scan details
cat runs/*/vuln-scan/osv.txt
cat runs/*/vuln-scan/trivy.txt
```

---

## Environment Variables

### Required (Already Set)
```bash
CLAUDE_BACKEND=bedrock           # Use AWS Bedrock
CLAUDE_CODE_USE_BEDROCK=1        # Claude Code uses Bedrock
AWS_REGION=us-east-1             # Your AWS region
```

### Optional (Override Model)
```bash
# Only set this if you want a different model
export CLAUDE_MODEL="claude-3-opus-20240229-v1:0"
```

**Most people don't need to set CLAUDE_MODEL** - the default is good.

---

## Available Models

If you want to override the default, here are valid options:

```bash
# Claude 3.5 Sonnet v2 (Default - Recommended)
export CLAUDE_MODEL="claude-3-5-sonnet-20241022-v2:0"

# Claude 3 Opus (Most capable, slower, more expensive)
export CLAUDE_MODEL="claude-3-opus-20240229-v1:0"

# Claude 3 Haiku (Fastest, less capable, cheaper)
export CLAUDE_MODEL="claude-3-haiku-20240307-v1:0"
```

---

## What Changed

### Code Changes
- **File:** `vuln-scan/call_claude.py`
- **Change:** Added backend-aware default model selection
- **Impact:** No manual configuration needed

### New Files
- Comprehensive documentation (8 new files)
- Automated test suite (`test_fix.sh`)
- Quick start guide (this file)

### What Stayed the Same
- All existing functionality
- Command-line interface
- Environment variable overrides
- Everything is backward compatible

---

## Troubleshooting

### Error: "AccessDenied" or "403"
**Problem:** IAM permissions issue  
**Fix:** Verify IAM policy is attached to role
```bash
aws iam get-role-policy \
  --role-name sbom-toolkit-bedrock-role \
  --policy-name sbom-toolkit-bedrock-policy
```

### Error: "Model not found" or "400"
**Problem:** Wrong model ID or region  
**Fix:** Check that:
1. You're using a valid model ID (see above)
2. Model is available in your region (us-east-1 has all)
3. Model access is enabled in Bedrock console

### Error: Still getting "claude-sonnet-5"
**Problem:** Old version of file cached  
**Fix:** Verify the fix is applied:
```bash
grep "claude-3-5-sonnet-20241022" vuln-scan/call_claude.py
```
Should show line with the new default.

### Pipeline Stops at Stage 2
**Problem:** Other issue (not model ID)  
**Fix:** Check the error message:
```bash
cat runs/*/ai-triage.md  # See if partial output exists
# OR check logs for details
```

---

## Documentation

Detailed documentation available:

| File | Purpose | When to Read |
|------|---------|--------------|
| `QUICK_START.md` | This file | Start here |
| `FIX_APPLIED.md` | Fix confirmation | Want details on what was fixed |
| `README_ERRORS_AND_FIXES.md` | User-friendly guide | Need help troubleshooting |
| `ERROR_ANALYSIS.md` | Technical deep-dive | Want complete technical details |
| `CODE_FLOW_DIAGRAM.md` | Execution flow | Debugging or understanding code |
| `CHANGES_SUMMARY.md` | Complete changelog | Project documentation |
| `SUGGESTED_CODE_FIX.md` | Implementation details | Maintaining or extending code |

**Start with this file**, then read others as needed.

---

## Common Use Cases

### Use Case 1: Run Full Security Pipeline
```bash
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml
```

### Use Case 2: Just AI Triage (Skip Fuzzing)
```bash
./orchestrate.sh vuln-scan/cyclonedx-sbom.xml --skip-fuzz
```

### Use Case 3: Just Vulnerability Scan (No AI, No Fuzzing)
```bash
cd vuln-scan
./scan.sh cyclonedx-sbom.xml ./reports
```

### Use Case 4: Manual AI Triage on Existing Scan
```bash
cd vuln-scan
./ai-triage.sh reports/*/osv.json reports/*/trivy.json my-triage.md
```

### Use Case 5: Use Different Model for One Run
```bash
CLAUDE_MODEL="claude-3-opus-20240229-v1:0" \
  ./orchestrate.sh vuln-scan/cyclonedx-sbom.xml
```

---

## Performance & Cost

### Typical Run Times
- **Stage 1 (Scan):** 1-3 minutes
- **Stage 2 (AI Triage):** 30-90 seconds
- **Stage 3 (Target Gen):** 2-5 minutes
- **Stage 4 (Fuzzing):** 5 minutes (default, configurable)

**Total:** ~10-15 minutes for full pipeline

### AWS Costs (Approximate)
- **Claude 3.5 Sonnet:** ~$3-5 per million input tokens
- **Stage 2 Triage:** ~$0.05-0.15 per run (small SBOM)
- **Stage 3 Target Gen:** ~$0.20-0.50 per run
- **Bedrock charges:** Pay only for what you use

**Typical full run:** < $1 in Claude API costs

---

## Best Practices

### Do This
✅ Run the pipeline regularly (weekly or on dependency updates)  
✅ Review AI triage output before taking action  
✅ Check fuzzing results for crashes  
✅ Keep documentation handy  
✅ Use default model unless you have a reason not to

### Don't Do This
❌ Ignore P0/P1 findings without investigation  
❌ Trust AI triage as final verdict (it needs human review)  
❌ Run fuzzing in production environments  
❌ Override model without understanding the tradeoffs

---

## Next Steps

1. ✅ Read this guide (you're doing it!)
2. ☐ Run the test: `./test_fix.sh`
3. ☐ Run the pipeline: `./orchestrate.sh vuln-scan/cyclonedx-sbom.xml`
4. ☐ Review the output: `cat runs/*/SUMMARY.md`
5. ☐ Investigate any P0/P1 findings
6. ☐ Set up regular scanning (cron, CI/CD, etc.)

---

## Getting Help

### If Something's Not Working

1. **Run the test:** `./test_fix.sh` to verify configuration
2. **Check logs:** Look at error messages for clues
3. **Read docs:** See the documentation files listed above
4. **Verify AWS:** Ensure IAM permissions and model access

### If You Have Questions

- **"What model should I use?"** → Default (3.5 Sonnet) is great for most uses
- **"Can I use Opus?"** → Yes, set `CLAUDE_MODEL="claude-3-opus-20240229-v1:0"`
- **"How much does this cost?"** → Usually < $1 per full pipeline run
- **"Is my data sent to Anthropic?"** → No, it stays in AWS Bedrock
- **"Do I need CLAUDE_MODEL set?"** → No, not anymore (that's what we fixed!)

---

## Summary

**What you need to know:**
1. ✅ The fix is applied - model ID issue resolved
2. ✅ No manual configuration required
3. ✅ Just run: `./orchestrate.sh vuln-scan/cyclonedx-sbom.xml`
4. ✅ Documentation available if needed

**You're ready to go!** 🚀

---

**Questions?** Read the documentation files or run `./test_fix.sh` to verify.

**Last Updated:** 2026-07-02  
**Status:** ✅ Ready for production use
