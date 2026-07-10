# UI Roadmap

A UI is useful now, but it should start small. The project should not become a large web app before the CLI workflow is stable.

## Recommended first UI

Start with a static local report UI generated from CLI outputs:

- No login.
- No server.
- No database.
- No uploaded sensitive artifacts stored anywhere.
- Opens from `reports/ui/index.html`.

This keeps the project easy to run and safe for source-available release.

## Later UI options

Phase 2 can add a local-only web UI:

- FastAPI backend.
- Read-only project workspace.
- Drag-and-drop SBOM upload.
- Quality score view.
- Policy results.
- Scanner comparison.
- Supplier follow-up questions.
- VEX template generation.

Phase 3 can add multi-user features only if needed:

- Authentication.
- Database-backed project history.
- Role-based access.
- Secrets management.
- Background job queue.

## Recommendation

For now, keep the UI as a generated static dashboard. Add a full web app only after the CLI commands and report schema settle.
