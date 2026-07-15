# Contributing

1. Create a focused branch from `dev`.
2. Run `gofmt -w .`, `go vet ./...`, and `go test -race ./...`.
3. Add tests for protocol parsers, state transitions, persistence, or failure behavior changed by the patch.
4. Keep network and device input bounded and treat it as hostile.
5. Preserve SPDX headers and use `Apache-2.0` for new source files.
6. Explain durability, compatibility, and migration effects in the pull request.

Protocol changes must include cross-language golden vectors shared with `latch` and `protocol`.
