# List available recipes
default:
    @just --list

# Install development tools
setup:
    cargo install taplo-cli cargo-edit cargo-outdated cargo-release git-cliff
    rustup component add rustfmt clippy

# Run all CI checks
ci:
    cargo check --all-targets
    cargo fmt -- --check
    taplo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-targets --all-features
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Run check
check:
    cargo check --all-targets

# Run tests
test *ARGS:
    cargo test --all-targets --all-features {{ ARGS }}

# Run clippy
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
    cargo fmt
    taplo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check
    taplo fmt --check

# Build documentation
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Show outdated dependencies
outdated:
    cargo outdated

# Update dependency versions in Cargo.toml
upgrade:
    cargo upgrade

# Update Cargo.lock
update:
    cargo update

# Run benchmarks
bench *ARGS:
    cargo bench {{ ARGS }}

# Generate CHANGELOG from git history
changelog:
    git-cliff -o CHANGELOG.md

# Publish to crates.io (called from GitHub Actions)
publish:
    cargo publish

# Bump version, generate changelog, commit, and tag
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo release version {{version}} --execute --no-confirm
    git-cliff --tag "v{{version}}" -o CHANGELOG.md
    git add -A
    git commit -m "chore(release): v{{version}}"
    git tag -a "v{{version}}" -m "v{{version}}"
    echo "Review the commit, then run: git push --follow-tags"
