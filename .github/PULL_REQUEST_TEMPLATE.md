# Pull Request

## Description
<!-- Provide a brief description of the changes in this PR -->

## Type of Change
<!-- Mark the relevant option with an "x" -->
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test addition or improvement
- [ ] 🔒 Security improvement

## Component
<!-- Mark the relevant component(s) with an "x" -->
- [ ] Kernel
- [ ] Container Runtime (containerd/runc)
- [ ] ZiroPkg Package Manager
- [ ] Ziro-Dev SDK
- [ ] Networking (CNI)
- [ ] Security
- [ ] Monitoring
- [ ] Cloud Images
- [ ] Documentation
- [ ] CI/CD
- [ ] Other: ___________

## Related Issues
<!-- Link to related issues using "Fixes #123" or "Closes #123" -->
- Fixes #
- Related to #

## Changes Made
<!-- Describe the changes made in detail -->
- 
- 
- 

## Testing
<!-- Describe how you tested your changes -->
- [ ] Unit tests pass (`make test`)
- [ ] Integration tests pass (`make test-full`)
- [ ] Manual testing performed
- [ ] New tests added for new functionality

### Test Commands Run
```bash
# List the commands you ran to test your changes
make test-smoke
make test-container
```

## Screenshots/Logs
<!-- If applicable, add screenshots or logs to help explain your changes -->

## Checklist
<!-- Mark completed items with an "x" -->
- [ ] My change follows the [design standard](https://github.com/ziro-os/ziro-os/blob/main/docs/design/README.md) (an accepted [RFC](https://github.com/ziro-os/ziro-os/blob/main/docs/design/rfcs/README.md) for new resource kinds, API/schema or security model changes)
- [ ] I have performed a self-review of my code
- [ ] I have added tests (unit, and `tests/qemu/boot-smoke.py` where a booted host is needed); new and existing tests pass locally
- [ ] Lint gate is clean: `gofmt -l` prints nothing, `go vet`, `staticcheck` and `shellcheck -S warning` report nothing ([commands](https://github.com/ziro-os/ziro-os/blob/main/community/CONTRIBUTING.md#lint-gate))
- [ ] API changes: route table, `sdk/openapi.yaml` (with `x-ziro-role`) and the `sdk/client` method are updated
- [ ] I have updated the documentation in `docs/`
- [ ] Any dependent changes have been merged and published

## Breaking Changes
<!-- If this is a breaking change, describe what breaks and how to migrate -->

## Additional Notes
<!-- Any additional information that reviewers should know -->

## Reviewer Notes
<!-- For maintainers: any specific areas to focus on during review -->

---

Thank you for contributing to Ziro-OS! 🚀