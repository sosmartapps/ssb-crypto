# Versioning Strategy

This document describes how we manage versioning of the mlkem-native dependency.

## Current Version

- **mlkem-native**: `v1.0.0` (pinned to stable release)
- **Commit**: `048fc2a7a` (Merge pull request #1081 from pq-code-package/release-typo)

## Versioning Approach

We use git submodules to include mlkem-native as a dependency. This approach provides:

1. **Reproducible builds**: Exact same version across all environments
2. **Security**: We can audit the exact code being used
3. **Stability**: No unexpected breaking changes from upstream

