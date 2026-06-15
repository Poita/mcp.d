---
name: release-helper
description: Cut a release following this project's checklist and conventions
license: Apache-2.0
metadata:
  version: "1.3.0"
  audience: maintainers
---

# Release Helper

Follow these steps to cut a release.

1. Confirm CI is green on `main`.
2. Run through `references/CHECKLIST.md` and tick every item.
3. Tag `vX.Y.Z`, push the tag, and let the release workflow publish.
