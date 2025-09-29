# Tests

Integration and automated test harnesses for Ziro-OS.

## Structure
- `smoke/` - Basic smoke tests (boot, container run)
- `integration/` - Full integration test suite
- `performance/` - Performance benchmarks
- `security/` - Security validation tests

## Running Tests
```bash
make test-smoke    # Quick smoke tests
make test-full     # Full test suite
make test-qemu     # QEMU-based tests
```