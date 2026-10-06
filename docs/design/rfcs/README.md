# RFCs

An RFC records a design decision before it is built, so reviewers can agree on the shape of a change rather than
reverse-engineer it from a diff.

## When an RFC is needed

- A new resource kind, or a new top-level section in an existing one.
- A change to the REST API or a schema that existing users or SDK clients would notice (new required fields,
  removed or renamed fields, changed meaning, new roles).
- A change to the security model: who may do what, how secrets travel, what is signed and with which key, what
  is trusted at boot.

Bug fixes, new optional fields, new commands that follow the [design standard](../README.md) and documentation do
not need one.

## Process

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md` (the next free number) and open a pull
   request with it. The implementation may be in the same pull request or follow it.
2. Discussion happens on the pull request. Update the RFC as the design changes.
3. Merging the RFC means it is accepted. A later RFC can supersede it; mark the old one "Superseded by NNNN".

## Index

| RFC | Title | Status |
|---|---|---|
| [0001](0001-stacks-and-host-config.md) | Stacks and declarative host config | Accepted (implemented in #49) |
| [0002](0002-dns-provider.md) | Public DNS provider for the gateway's names | Accepted (implemented in #91)|
