# Changelog

## 0.1.0 - 2026-10-15

First release, built on stutters-mcp-core 0.1.0 and tested against CML 2.10.0.

- 46 tools: 25 read, 15 write (preview-first), 6 dangerous.
- JWT login (`/api/v0/auth_extended`, falling back to `/authenticate`) with expiry taken from the
  token; `CML_TOKEN` for a pre-issued JWT.
- The controller's OpenAPI document powers `cml_search_spec`, `cml_get_definition` and `cml_api_call`.
- Name-or-id resolution for labs and nodes; links by id or `r1<->r2` endpoints.
- Task tools: `cml_build_lab` (compact spec -> lab, automatic interface allocation),
  `cml_wait_for_converged` (with progress), `cml_diff_lab` (lab vs lab or saved YAML).
- Console, VNC and pcap access keys are never returned. pyATS passwords are masked in nodes,
  exports and testbeds.
- Docker image (non-root, read-only rootfs) for the HTTP transport.
