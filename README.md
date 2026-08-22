# TENEMENT

TENEMENT is a small self-hosted service for personal homepages. Each tenant gets a constrained file area and a browser-based interface for creating, editing, uploading, and serving a tiny static site.

The application is intentionally compact: the server, HTML templates, account system, session handling, editor, and tenant-site serving logic live in one Go program.

## Features

- Account registration and bcrypt password hashing
- Server-side sessions and CSRF protection
- Browser-based file manager and text editor
- Static tenant homepages
- Per-tenant quotas: 2 MiB and 128 files by default
- JSON/file-backed persistence with no external database
- Security headers and path validation

## Run locally

Requirements: Go 1.25 or later.

```bash
go run .
```

TENEMENT listens on http://localhost:8080 by default. Set `PORT` to use another port:

```bash
PORT=3000 go run .
```

## Build

```bash
go build -o tenement .
./tenement
```

## Runtime data

TENEMENT creates runtime state under `data/`, including password hashes, sessions, and tenant files. That directory is intentionally ignored by Git. Back it up securely and never commit it.

## Security and deployment

This is an experimental small-hosting service, not a professionally audited multi-tenant platform. Before exposing it publicly, place it behind HTTPS, review resource limits and abuse controls, secure filesystem permissions, and establish reliable backups.
