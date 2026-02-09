# lockfile-lint

[![npm version](https://img.shields.io/npm/v/@lxgicstudios/lockfile-lint.svg)](https://www.npmjs.com/package/@lxgicstudios/lockfile-lint)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Verify your package-lock.json integrity and security. Checks all resolved URLs point to the official npm registry, detects insecure git:// protocol dependencies, and verifies your lockfile stays synced with package.json.

## Install

```bash
# Run directly with npx
npx @lxgicstudios/lockfile-lint

# Or install globally
npm install -g @lxgicstudios/lockfile-lint
```

## Usage

```bash
# Check package-lock.json in current directory
lockfile-lint

# Check a specific directory
lockfile-lint ./my-app/

# CI mode (exits with code 1 on errors)
lockfile-lint --ci

# Strict mode (treats warnings as errors)
lockfile-lint --ci --strict

# Allow a private registry
lockfile-lint --allow-registry https://npm.mycompany.com

# JSON output for pipelines
lockfile-lint --json
```

## Features

- **Zero dependencies** - uses only built-in Node.js modules
- Verifies all resolved URLs point to official npm registry
- Detects insecure git:// protocol (no encryption)
- Catches HTTP (non-HTTPS) resolved URLs
- Verifies integrity hashes are present
- Checks lockfile is synced with package.json
- Detects file: protocol references
- Supports lockfile versions 1, 2, and 3
- CI mode with configurable strictness
- JSON output for pipeline integration
- Allows whitelisting private registries

## Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--json` | Output results as JSON |
| `--ci` | Exit with code 1 if any errors found |
| `--strict` | Treat warnings as errors |
| `--allow-registry <url>` | Allow an additional registry (repeatable) |
| `--allow-git` | Allow git:// protocol dependencies |
| `--allow-github` | Allow GitHub shorthand dependencies |
| `--verbose` | Show detailed info for each finding |

## Rules

| Rule | Severity | What it checks |
|------|----------|---------------|
| `registry-url` | Error | All resolved URLs use official npm registry |
| `git-protocol` | Error/Warning | No insecure git:// protocol |
| `https-only` | Error | All URLs use HTTPS |
| `integrity` | Warning | All packages have integrity hashes |
| `sync-check` | Error/Warning | Lockfile matches package.json |
| `no-file-refs` | Warning | No file: protocol references |
| `lockfile-version` | Info | Lockfile version check |

## Why This Matters

Supply chain attacks are real. If someone swaps a registry URL in your lockfile to point at a malicious registry, you'll install compromised packages without knowing it. This tool catches that.

It also catches common issues like lockfile drift (when your lockfile doesn't match package.json) and insecure protocols.

## License

MIT - [LXGIC Studios](https://github.com/lxgicstudios)
