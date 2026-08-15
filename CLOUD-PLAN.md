# Relay — Cloud Deployment Plan

**Status:** Local changes complete. Pending approval to push.

## Repository Settings

### Visibility
- [ ] Change from private to **public**

### Default branch
- [ ] Set `main` as default branch (already in place)

### Repository topics
- [ ] Add topics: `relay`, `lep`, `gateway`, `firmware`, `diagnostics`, `embedded`, `open-source`, `apache-2.0`, `go`, `docker`

## Branch Protection (main)

Enable branch protection on `main`:

- [ ] **Require pull request reviews before merging** — 1 approver minimum
- [ ] **Dismiss stale pull request approvals when new commits are pushed**
- [ ] **Require review from Code Owners** — CODEOWNERS file already configured
- [ ] **Require status checks to pass before merging**
  - [ ] `CI / test (ubuntu-latest)` (must pass)
  - [ ] `CI / test (windows-latest)` (must pass)
  - [ ] `CI / test (macos-latest)` (must pass)
  - [ ] `CI / security` (must pass)
  - [ ] `CI / docker` (must pass)
- [ ] **Include administrators** — recommend yes for this repo
- [ ] **Restrict who can push to matching branches** — @TheusHen only

## Tags

Tag policy:
- [ ] Tags must follow `v<major>.<minor>.<patch>` format
- [ ] Tags must be annotated (not lightweight)
- [ ] Tags must point to a commit reachable from `main`
- [ ] Tag creation restricted to maintainers
- [ ] Require CHANGELOG entry for each tagged version

## Issue Configuration

Already configured locally:
- [x] `blank_issues_enabled: false`
- [x] Contact links: Discussions, Security advisory, Contributing guide
- [x] Issue templates: bug.yml, feature.yml

## Pull Request Configuration

Already configured locally:
- [x] Pull request template with durability, security, and runtime evidence checks
- [x] Required status checks: all CI jobs

## Automation

Already configured locally:
- [x] Dependabot: gomod + github-actions, weekly
- [x] Labeler: lep, delivery, spool, admin, crypto, sources, analysis, cli, ci, documentation, packaging
- [x] CODEOWNERS: core internal packages require maintainer review
- [x] Stale bot: 60 days issues, 45 days PRs
- [x] CodeQL: weekly scan on main + PR checks (Go)
- [x] Release workflow: validates CHANGELOG entry, cross-platform build, Docker build, GitHub release

## GitHub Discussions

- [ ] Enable GitHub Discussions for the repository
- [ ] Configure discussion categories:
  - `proposal` — architectural proposals
  - `question` — integration and operations questions
  - `show-and-tell` — deployments and use cases

## Security

- [ ] Enable GitHub Secret Scanning
- [ ] Enable Dependabot security updates (already configured)
- [ ] Configure security policy URL (already set in SECURITY.md)
- [ ] Enable private vulnerability reporting (already configured)

## Actions

Recommended actions to pin (already using pinned versions in workflows):
- `actions/checkout@v7` (3d3c42e5aac5ba805825da76410c181273ba90b1)
- `actions/setup-go@v5`
- `actions/upload-artifact@v7` (043fb46d1a93c77aae656e7c1c64a875d1fc6a0a)
- `actions/stale@v11` (4391f3da665fdf50b6810c1a66712fb9ba21aa93)
- `github/codeql-action@v3`
- `docker/setup-buildx-action@v3`

## Pre-Push Checklist

Before making the repo public:

- [ ] All secrets removed from git history (`git log -p` search for keys, tokens, endpoints)
- [ ] `.gitignore` is comprehensive (already in place, covers /data, /inbox, relay.yaml, *.db)
- [ ] `relay.yaml.example` contains only placeholder values (no real endpoints/tokens)
- [ ] No production captures in test fixtures
- [ ] No private Trace backend internals documented
- [ ] LICENSE file present and correct (Apache-2.0, already present as LICENSE.md)
- [ ] All documentation files review for sensitive content
- [ ] Dockerfile doesn't copy secrets or build context with sensitive files
- [ ] Branch protection rules drafted and ready to apply
