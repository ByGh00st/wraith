# Wraith v1.4.7 → v1.5.0 Stabilization Gate

> **Status:** FEATURE FREEZE ACTIVE  
> **Target Release:** v1.5.0 (Stabilization Release)  
> **Enforcement:** Zero new features, zero experimental flags.  

---

## 1. Feature Freeze Policy

Starting from tag `v1.4.7` on branch `stabilization/v1.5.0`, all feature development is officially frozen.
The sole objective of this branch is hardening, kernel-grade E2E test verification, parser fuzzing, multi-distribution compatibility, and Debian packaging compliance.

### Allowed Commit Types:
- `fix(*)`: Critical bug fixes, memory leak resolution, race condition elimination.
- `test(*)`: E2E network namespace scenarios, libFuzzer targets, unit/regression tests.
- `ci(*)`: GitHub Actions workflows, matrix automation, container environments.
- `docs(*)`: Threat model updates, groff manpages, architectural documentation.
- `chore(*)`: Dependency pruning, packaging metadata, linting.

**Commits of type `feat(*)` will be rejected unconditionally.**

---

## 2. Six-Phase Stabilization Roadmap

1. **Phase 0:** Feature Freeze & Branch Discipline (Enacted).
2. **Phase 1:** Live Linux Kernel E2E Integration Testing (Network Namespace Sandbox).
3. **Phase 2:** Parser Fuzzing Test Infrastructure (`cargo-fuzz` / `libFuzzer`).
4. **Phase 3:** Multi-Distribution Compatibility Matrix (Kali, Debian 12, Ubuntu 24.04, Arch, Alpine).
5. **Phase 4:** Debian Package Quality Audit (`lintian` & Zero-Orphan `postrm` Purge).
6. **Phase 5:** Documentation Hardening, Evidence Synchronization & v1.5.0 Tagging.

---

*Governed by NYX-PRIME Sovereign Autonomous Engineering Kernel.*
