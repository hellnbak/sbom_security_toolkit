# Scheduler, Job Lifecycle, and Evidence Retention

v2.6.0 adds operational helpers for self-hosted deployments.

## Scheduler runner

Schedules are defined through the enterprise config layer and executed by the scheduler runner.

```bash
make enterprise-schedule SCHEDULE_NAME=nightly-full-scan WORKFLOW=analyze-everything CADENCE=daily
make scheduler-run
```

The first implementation is deliberately conservative: dry-run by default, records due schedule history, and can be executed with `EXECUTE=1`.

```bash
make scheduler-run EXECUTE=1
```

## Job lifecycle controls

```bash
make jobs-list
make job-cancel JOB_ID=<job-id>
make job-retry JOB_ID=<job-id>
make job-rerun JOB_ID=<job-id> NEW_JOB_ID=<new-job-id>
```

Cancel and retry requests are recorded as marker files and status updates so workers can honor them safely.

## Evidence retention

Dry-run cleanup:

```bash
make evidence-cleanup RETENTION_DAYS=90
```

Delete matching expired evidence artifacts:

```bash
make evidence-cleanup RETENTION_DAYS=90 DELETE=1
```

Release-blocking evidence should be exported or archived before automated cleanup.
