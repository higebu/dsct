# List available recipes
default:
    @just --list

# Install development tools
setup:
    cargo install taplo-cli cargo-edit cargo-outdated git-cliff release-plz
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

# Preview the release-plz release PR without making any changes
release-dry-run:
    release-plz update --dry-run
