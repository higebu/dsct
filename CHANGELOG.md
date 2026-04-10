## [0.2.5] - 2026-04-10

### 🚀 Features

- Add Gemini CLI extension support

### 📚 Documentation

- Add OpenAI Codex CLI setup instructions
## [0.2.4] - 2026-04-09

### 🐛 Bug Fixes

- *(tui)* Reject capture file truncation in refresh

### 📚 Documentation

- *(readme)* Fix dsct read JSON sample to match serializer
- *(mcp)* Mention sample_rate in dsct_read_packets description

### 🎨 Styling

- *(field_format)* Apply cargo fmt

### 🧪 Testing

- *(field_format)* Cover format_field_to_string edge cases
- *(stats)* Add inline unit tests for remaining modules
- Add cli streaming edge case tests
- *(filter)* Add e2e tests for -f filter expressions
- *(tui)* Add memmap safety smoke tests
- *(tui)* Add unit tests to modules lacking cfg(test)
- Add error, subcommand, and output schema coverage
- *(read)* Add integration tests for field-config, progress, esp-sa

### ⚙️ Miscellaneous Tasks

- Update README.md
- Add codecov badge to README.md
- *(release)* V0.2.4
## [0.2.3] - 2026-04-07

### ⚙️ Miscellaneous Tasks

- Add all-features=true to dist-workspace.toml
- *(release)* V0.2.3
## [0.2.2] - 2026-04-07

### ⚙️ Miscellaneous Tasks

- Add support for homebrew
- *(release)* V0.2.2
## [0.1.2] - 2026-04-06

### ⚙️ Miscellaneous Tasks

- Taplo fmt
- Remove aarch64-pc-windows-msvc from targets
- *(release)* V0.1.2
## [0.1.1] - 2026-04-06

### ⚙️ Miscellaneous Tasks

- Support claude plugin
- Update README.md
- Update justfile
- *(release)* V0.1.1
## [0.1.0] - 2026-04-06

### ⚙️ Miscellaneous Tasks

- Initial commit
- Add renovate.json
- *(release)* V0.1.0
