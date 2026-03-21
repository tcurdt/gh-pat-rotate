# gh-pat-rotate

Rotate a GitHub Personal Access Token into a fixed environment secret across a list of repositories.

GitHub does not provide an API to create PATs.
This tool handles the distribution step: you create the PAT manually, `gh-pat-rotate` pushes it everywhere.

## Prerequisites

- [`gh`](https://cli.github.com/) installed and authenticated (`gh auth status`)
- Repos file at `~/.releases` (or a custom path)

## Usage

```
gh-pat-rotate [--repos <path>] [--secret-name <name>] [--environment <name>]
```

Run it:

```sh
gh-pat-rotate
```

It will:

1. Print the required PAT settings and open `github.com/settings/tokens` in your browser
2. Prompt for the PAT (input is masked)
3. Validate the PAT against the GitHub API
4. For each repo: create the environment if missing, then upsert the secret
5. Print a per-repo status and a final summary

## Flags

| Flag            | Default       | Description                     |
| --------------- | ------------- | ------------------------------- |
| `--repos`       | `~/.releases` | Path to the repo list file      |
| `--secret-name` | `PAT_RELEASE` | Secret name to create or update |
| `--environment` | `release`     | Target environment name         |

## Repos file

One `owner/repo` per line. Comments and blank lines are ignored.

```
# release targets
alice/service-a
alice/service-b
team-x/release-tool
```

## PAT settings

When prompted, create a **classic** token with:

- Scopes: `repo`, `write:packages`
- Expiry: 90 days (or as short as you like)

## Output

```
alice/service-a updated
alice/service-b updated
team-x/release-tool failed: ensure environment: GET environment returned status 403

total: 3, updated: 2, failed: 1
```

Exit codes:

- `0` — all repos updated
- `1` — one or more repos failed
- `2` — fatal error (bad config, invalid PAT, auth failure)

## Piped usage

```sh
echo "ghp_..." | gh-pat-rotate
```

When stdin is not a terminal, the PAT is read from the pipe. Press Ctrl+D to signal end of input when using `cat |`.

## How it works

Secrets are encrypted client-side using libsodium's `crypto_box_seal` (ephemeral X25519 + XSalsa20-Poly1305) before being sent to the GitHub API. The PAT is never stored to disk or printed.

## License

Apache 2.0
