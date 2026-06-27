# Contributing to Soal

Thank you for your interest in contributing to Soal! We welcome contributions that help us build a high-quality, reliable, sovereign protocol for personal and community data.

## Project Philosophy

Soal aims for:
- **Sovereignty first**: Data stays under user control by default.
- **High quality code**: Small, focused, well-tested modules.
- **Incremental delivery**: Every phase produces a working, useful artifact.
- **Clear documentation** and rationale for decisions.

We follow the principles laid out in [spec.md](./spec.md).

## Governance

This project is currently under a **BDFL model** with Jeffrey Stewart (@soaljack) as founder. Architectural and directional decisions are made to maintain focus and quality. We aim to evolve toward broader community governance as the project matures.

## Getting Started

1. **Fork and clone** the repository.
2. **Install Rust** (stable). We recommend using the pinned toolchain (see `rust-toolchain.toml`).
3. **Build and test**:
   ```bash
   cargo build
   cargo test
   ./scripts/test-phase0.sh   # optional: full E2E validation
   ```

## Development Guidelines

- **Code style**: Run `cargo fmt` and `cargo clippy -- -D warnings` before submitting.
- **Testing**:
  - Add unit/property tests for core logic (we use `proptest`).
  - Add or update E2E tests in `tests/e2e.rs` for CLI behavior.
  - All tests must pass (`cargo test`).
- **Commits**: Use clear, descriptive commit messages. Reference issues when relevant.
- **Incremental changes**: Prefer small, reviewable PRs that deliver value (see the phased roadmap in spec.md).
- **Documentation**: Update relevant docs (README, spec.md comments, etc.) when behavior changes.
- **Code Quality** (from spec):
  - Small, focused functions and modules.
  - Comprehensive documentation and examples.
  - Test coverage for all core invariants.
  - Clear error handling and observability.

## Coding Standards

Please follow the spirit of the implementation guidelines in [spec.md](./spec.md):

- Rust-first, high-quality, testable code.
- Modular structure (`soal-core`, etc. as the project grows).
- Cross-platform compatibility from the start.

## Pull Request Process

1. Create a feature branch from `main`.
2. Make your changes following the guidelines above.
3. Ensure CI passes (formatting, clippy, tests on Linux/macOS/Windows).
4. Open a Pull Request with a clear description of the change and motivation.
5. Be responsive to review feedback.

PRs will be reviewed with the goal of maintaining code quality and alignment with the project vision.

## Reporting Issues

- Use GitHub Issues.
- For security issues, please see [SECURITY.md](./SECURITY.md).
- Provide as much detail as possible: reproduction steps, environment, expected vs actual behavior.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the dual MIT/Apache-2.0 license (see [LICENSE](./LICENSE)).

Thank you for helping make Soal better! Your data, your network, your rules.
