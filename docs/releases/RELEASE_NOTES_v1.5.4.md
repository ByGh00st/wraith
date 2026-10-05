# Wraith v1.5.4 — Narrowed Session Cleanup Scope

This release removes host system-log and shell-history erasure, swap and kernel/network cache purging, process-name spoofing, and debugger-triggered process termination. The corresponding CLI switches, strict-mode hooks, installer arguments, and help/demo text are removed.

The standalone cleanup command and purge hotkey are removed because they operated on operating-system logs, caches, and swap. Wraith-owned in-memory vault data remains scoped to its owning session object and is released with that object's lifecycle. Normal session teardown continues to restore recorded Wraith-managed settings without erasing operating-system logs, histories, swap devices, or kernel caches.

The release also removes the obsolete cleanup and anti-debug modules, updates the local Wiki and translated CLI text, and corrects historical notes to identify the retired swap-cleanup path.
