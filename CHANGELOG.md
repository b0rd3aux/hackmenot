# Changelog

All notable changes to hackmenot will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-13

### Added
- **Parallel Scanning Architecture**: Process-based parallel scanning for enterprise-scale performance
  - Scan 10k files in under 10 seconds on 8-core machines
  - Memory-efficient: <2GB for 50k file scans
  - Zero external dependencies (pure Python multiprocessing)
- **CLI Flags**:
  - `--parallel/--no-parallel`: Toggle parallel scanning (default: enabled)
  - `--workers`: Control number of worker processes
- **Parser Caching**: Automatic parser instance reuse within workers for memory efficiency
- **Automatic Rule Loading**: Rules loaded from RuleRegistry by default
- **Graceful Shutdown**: Handle Ctrl+C cleanly with worker cleanup
- **File Discovery**: Security-aware file discovery with symlink escape protection

### Changed
- **Default Scanning Mode**: Parallel scanning is now the default (use `--no-parallel` for sequential)
- **Performance**: Significant speed improvements for large codebases
- **Memory Usage**: Optimized memory footprint with lazy file discovery and parser caching

### Fixed
- Symlink escape protection now checks all files, not just symlinks
- .egg-info directories properly filtered during file discovery
- Consistent exception handling across all parsers

### Known Issues
- `.hackmeignore` integration with parallel scanner (7 failing tests)
  - Workaround: Use `--no-parallel` for full .hackmeignore support
  - Will be fixed in v2.0.1

## [1.1.0] - 2026-02-10

### Added
- Rust language support with tree-sitter parser
- Java language support with tree-sitter parser
- 20 new security rules (10 for Rust, 10 for Java)

### Changed
- Improved code quality with ruff and mypy enforcement
- Enhanced development tooling (pre-commit hooks)

## [1.0.1] - 2026-01-30

### Added
- Initial public release
- Support for Python, JavaScript/TypeScript, Go, Terraform
- 100+ security rules
- Multiple output formats (terminal, JSON, SARIF)
- Auto-fix capabilities
- GitHub Actions integration

[2.0.0]: https://github.com/b0rd3aux/hackmenot/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/b0rd3aux/hackmenot/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/b0rd3aux/hackmenot/releases/tag/v1.0.1
