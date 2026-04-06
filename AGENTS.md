# AGENTS.md — dsct

## Project Overview

`dsct` is an LLM-friendly packet dissector CLI built on top of the
`packet-dissector` family of crates.

- **Rust edition**: 2024
- **MSRV**: see `rust-version` in `Cargo.toml`
- **Primary purpose**: machine-consumable packet analysis, not human-first terminal output
- **Dependency boundary**: this repo consumes public crates from the
  `packet-dissector` repository via git dependencies

## Repository Layout

```text
Cargo.toml                 # Standalone crate manifest
src/                       # Library + CLI implementation
tests/                     # Integration / CLI tests
benches/                   # Criterion benchmarks
docs/                      # Supporting documentation
.github/workflows/ci.yml   # CI source of truth
```

## Build, Test, and Validation

CI is defined in `.github/workflows/ci.yml`. Run the same checks locally before
committing:

```bash
cargo test --all-targets
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
taplo fmt --check
```

Useful development commands:

```bash
cargo build
cargo test <test_name>
cargo bench
```

If `taplo` is not installed:

```bash
cargo install taplo-cli
```

## Development Rules

### General Principles

- Fix root causes, not symptoms.
- Keep the CLI predictable for agents; avoid clever output shortcuts.
- Prefer correctness and explicit errors over convenience.
- Do not add compatibility shims unless they are clearly required.
- Be direct in reviews: unclear behavior, weak validation, and schema drift are bugs.

### TDD Required

All non-trivial changes should follow test-first development:

1. Add or update tests first
2. Confirm the test fails for the intended reason
3. Implement the change
4. Re-run tests until green
5. Refactor without changing behavior

When changing existing behavior, update the tests first to reflect the new
expected behavior.

## CLI Design Constraints

### Structured Output

- Commands must produce structured JSON or JSONL output.
- Output must remain stable and machine-consumable.
- Do not add presentation-oriented formatting that makes parsing harder.

### Structured Errors

- Errors and warnings must be emitted as structured JSON to stderr.
- Exit codes must stay aligned with the CLI contract documented in `README.md`.
- Do not silently ignore malformed input or invalid arguments.

### Streaming and Performance

- Preserve streaming behavior for large capture files.
- Avoid unnecessary intermediate `Vec`, `HashMap`, or `String` allocations in
  hot paths.
- Keep fast paths intact when no filters or transformations are active.

### Pipe-Friendly Behavior

- Continue to support stdin input (`-`) where applicable.
- Avoid changes that require seekable input unless explicitly scoped.

## Dependency Boundary

This repo depends on `packet-dissector`, `packet-dissector-core`,
`packet-dissector-pcap`, and `packet-dissector-test-alloc` from the
`packet-dissector` repository.

Rules:

- Treat those crates as external dependencies.
- Prefer consuming their public APIs as-is rather than reshaping them here.
- If a needed capability is missing, document the gap and add the corresponding
  API in `packet-dissector` rather than duplicating protocol logic in `dsct`.
- Keep `dsct` focused on CLI, filtering, formatting, MCP, and TUI concerns.

## Rust Coding Conventions

- No `unsafe` — enforced by `#![deny(unsafe_code)]` in `lib.rs`.
  `unsafe` is permitted only in `CaptureMap` (`src/tui/state.rs`) and
  `BgIndexer::spawn` (`src/tui/bg_indexer.rs`) for `memmap2` mmap operations,
  guarded by `#[allow(unsafe_code)]` with SAFETY comments.
- No `.unwrap()` / `.expect()` in `src/`; use `?` and contextual errors.
  `const` context `unwrap()` / `panic!` is permitted as it is evaluated at
  compile time and cannot cause runtime panics.
- Public items should have doc comments.
- Prefer small, explicit helpers over tangled control flow.
- Follow Rust naming conventions:
  - `snake_case` for functions, modules, and variables
  - `PascalCase` for types and traits
  - `SCREAMING_SNAKE_CASE` for constants
- No wildcard imports except `use super::*` in test modules.

## Testing Guidance

- Unit tests live alongside the code under `src/`.
- Integration and CLI behavior tests live under `tests/`.
- Benchmarks live under `benches/` using Criterion.
- Add tests for:
  - invalid arguments
  - malformed capture data
  - structured error output
  - filtering and schema behavior
  - protocol-specific display logic when behavior changes

## Documentation Guidance

- Keep `README.md` accurate for standalone repo usage.
- When CLI flags, output shape, or behavior change, update the README in the
  same change.
- Keep examples copy-pastable.

## CI and Release Notes

- `.github/workflows/ci.yml` is the source of truth for required checks.
- If you add a new mandatory local check, add it to CI too.
- Keep the repo independently buildable from the `packet-dissector` monorepo.

