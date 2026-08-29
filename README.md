# ctxprobe

A read-only CLI that statically scans markdown, HTML, and plaintext (files,
directories, or stdin) for **context-poisoning / prompt-injection patterns** —
the input/context half of agent security that `hook-scanner` covers for the
supply-chain half.

`ctxprobe` looks for the things an attacker hides in documents, scraped web
pages, and repo docs that later get fed to an LLM:

- **Hidden / embedded instructions** — "ignore all previous instructions",
  "disregard the above", override attempts.
- **System-prompt overrides** — `<|im_start|>system`, `system:` / `assistant:`
  role frames injected into untrusted content.
- **Instruction-looking text inside HTML comments, metadata, and `alt`
  attributes** — places a model-as-tool won't render but may still read.
- **base64 / hex blobs adjacent to instructions** — obfuscated payloads.
- **Zero-width and Unicode-confusable characters** — invisible text and
  homoglyph substitution.
- **Token-economy bribes** — "you will be rewarded", "here are 1000 tokens".
- **Role-play / jailbreak frames** — "you are now DAN", "act as a hacker".
- **Multi-stage "ask the AI" widget traps** — prompts that bait a model into
  acting as an agent.

## Install

No dependencies. Standard library only (Python 3.8+).

```bash
pip install -e .        # optional, provides the `ctxprobe` entry point
python -m ctxprobe scan --path doc.md
```

## Usage

```bash
# Scan a single file
python -m ctxprobe scan --path page.html

# Scan a directory tree
python -m ctxprobe scan --dir ./docs

# Read from stdin (e.g. raw scraped content)
curl -s https://example.com/page | python -m ctxprobe scan --stdin

# Machine-readable output
python -m ctxprobe scan --dir ./docs --json

# Quiet mode for CI (still exits non-zero on findings)
python -m ctxprobe scan --dir ./docs --json --quiet
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings (clean). |
| `1`  | One or more findings. |
| `2`  | Usage / I/O error. |

### Severity tiers

| Tier | What it means | Example |
|------|--------------|---------|
| `high`   | Explicit override / system-prompt injection | "ignore previous instructions", `<|im_start|>system` |
| `medium` | Embedded-instruction heuristic or obfuscation-adjacent | instructions in HTML comments, base64 next to "execute" |
| `low`    | Stylistic / ambient signal | zero-width chars, token bribes, role-play frames |

False positives on benign prose are expected for `low`/`medium`; tune by
reviewing the `--json` output rather than treating every line as a defect.

## Why

The framing comes from the 2026-08-07 AI/cyber research digest: *"the context
is the weapon"* — agent-tool flaws where attackers trigger tool use without the
model reading the prompt, and AI Recommendation Poisoning silently corrupting
LLM memory. `ctxprobe` gives you a cheap, offline first pass over anything you
might feed a model.

## Tests

```bash
python -m pytest tests/ -q
```

The suite includes an injected corpus (must trigger findings) and a benign
corpus (must yield **zero high-severity** findings).

## License

[MIT](LICENSE)
