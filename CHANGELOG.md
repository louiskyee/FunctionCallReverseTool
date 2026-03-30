# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-31

### Added

- Unified CLI framework with single entry point (`python -m function_call_tool`)
- `BaseBackend` abstract class for extensible backend architecture
- Ghidra backend with headless analyzer integration
- Radare2 backend with r2pipe integration
- Parallel processing with configurable worker multiplier per backend
- `--pattern` glob parameter for flexible file filtering
- DOT format output for function call graphs
- JSON format output for per-function disassembly
- Per-file timeout protection with pre-flight checks (Radare2)
- Automatic skip for already-processed files
- `pyproject.toml` with `[project.scripts]` entry point
- `python -m function_call_tool` support via `__main__.py`
- Docker deployment scripts for Ghidra and Radare2

### Fixed

- Use `time.perf_counter()` instead of `time.process_time()` for accurate wall-clock timing
- Guard `os.cpu_count()` with `or 1` fallback
- Rebuild loggers inside worker processes instead of passing across process boundaries
- Radare2 Dockerfile filename inconsistency (`install_radare2.sh` vs `radare2_deploy.sh`)
- Quote `$timeout_seconds` variable in `r2_timeout_check.sh`
