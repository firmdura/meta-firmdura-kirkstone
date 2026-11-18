---
description: "Preserve Linux artifact identities when exporting build evidence"
applyTo: "**"
---

Keep canonical Linux deploy handoffs as tar archives on case-insensitive
control hosts: `LICENSE.txt` and `License.txt` are distinct files in the
Yocto bzip2 licence output, but direct directory export silently collides.
Verify archive paths, sizes, SHA-256 values and symlink targets against the
Linux source inventory; a successful `docker cp` is not an integrity check.
Extract canonical handoff archives only on a case-sensitive filesystem.
Yocto also emits absolute aliases under the original deploy root; preserve
and validate those bindings rather than claiming an unchanged archive is
freely relocatable.
Follow [the build and storage contract](../../docs/build.md).
