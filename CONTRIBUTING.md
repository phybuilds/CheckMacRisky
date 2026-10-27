# Contributing

Thanks for helping keep this checklist accurate. The most useful contributions:

1. **Version corrections.** Link the vendor advisory or release note. Do not rely on news sites alone.
2. **Command fixes.** A command must be read-only in Phase 1, must not print secrets, and must not pipe downloads into a shell.
3. **Test reports.** Run the Phase 1 checks and add a row to TESTED-ON.md (macOS version, chip, result). Do not include usernames, paths or tokens.
4. **Updates.** When security versions change, update the README, bump "Last reviewed", and add a CHANGELOG entry.

## Rules for changes
- Keep the safety rules in the README intact.
- State the source and date for any new version number, and add it to VERIFICATION.md.
- Mark anything you could not verify as UNVERIFIED rather than guessing.

## Reporting an unsafe or wrong command
Open an issue using the template. If a command could cause data loss, say so in the title.
