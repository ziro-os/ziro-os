# Pull request

## Description

<!-- Summarize the change and the motivation for it. -->

## Type of change

<!-- Mark the relevant options with an "x". -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (existing functionality changes or stops working)
- [ ] Documentation
- [ ] Refactoring (no functional change)
- [ ] Performance improvement
- [ ] Tests
- [ ] Security improvement

## Components

<!-- Mark the affected components with an "x". -->

- [ ] Kernel
- [ ] Container runtime (containerd, runc)
- [ ] Gateway
- [ ] Cluster
- [ ] Router
- [ ] Sandboxes
- [ ] ziroctl or ziropkg
- [ ] zirocd
- [ ] SDK
- [ ] Networking (CNI, DNS, WireGuard)
- [ ] Security
- [ ] Cloud images
- [ ] Documentation
- [ ] CI/CD
- [ ] Other:

## Related issues

<!-- Link related issues, for example "Fixes owner/repo#123". -->

## Changes

<!-- List the changes in detail. -->

## Testing

- [ ] Unit tests pass (`make test`)
- [ ] The boot test passes where a booted host is involved (`make test-boot`)
- [ ] New tests cover new behavior
- [ ] Manual testing performed

Commands run:

```bash
# List the commands you ran to test the change.
```

## Screenshots or logs

<!-- Optional. Add output that helps explain the change. -->

## Checklist

- [ ] The change follows the [design standard](https://github.com/ziro-os/ziro-os/blob/main/docs/design/README.md). New
      resource kinds, API or schema changes,
      and security model changes have an accepted
      [RFC](https://github.com/ziro-os/ziro-os/blob/main/docs/design/rfcs/README.md).
- [ ] The author has reviewed the diff.
- [ ] Tests were added (unit tests, and `tests/qemu/boot-smoke.py` where a booted host is needed), and new and
      existing tests pass locally.
- [ ] The [lint gate](https://github.com/ziro-os/ziro-os/blob/main/community/CONTRIBUTING.md#lint-gate) is clean:
      `gofmt -l` prints nothing, and `go vet`,
      `staticcheck` and `shellcheck -S warning` report nothing.
- [ ] API changes update the route table, `sdk/openapi.yaml` (with `x-ziro-role`) and the `sdk/client` method.
- [ ] Documentation in `docs/` is updated.
- [ ] Dependent changes are merged and published.

## Breaking changes

<!-- If this is a breaking change, describe what breaks and how to migrate. -->

## Notes for reviewers

<!-- Areas that need particular attention. -->
