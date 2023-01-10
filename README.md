# ovl-idmap

Independent audit of OverlayFS copy-up ownership handling (Linux 6.1 era).

**TL;DR:** during a December 2022 audit of the copy-up path I found that
`ovl_copy_up_one()` never validates that the lower file's `st_uid`/`st_gid`
are mappable into the mounter's user namespace. Copy-up proceeds with the
mounter's credentials but stamps the upper copy with an unmapped owner,
which stat(2) later renders as the overflow id (`65534`). Combined with a
FUSE-backed lower layer, a setuid-capable file can cross a nosuid/mount
boundary into the upper layer and execute there — local privilege
escalation for any unprivileged user able to mount overlayfs in a userns
(generic since 5.11, `459c7c565ac3`).

## My fix (this repo)

`ovl-copyup-idmap.patch` — refuse the copy-up when the lower owner has no
mapping, at the same point the stat lands. Same class of fix you'd get by
asking "what would cp -a have done in the mounter's context?"

## Upstream resolution

While preparing this for wider disclosure I found upstream had merged an
equivalent fix by an independent path:

- commit `4f11ada10d0a` ("ovl: fail on invalid uid/gid mapping at copy up",
  Miklos Szeredi, mainline 6.2) — same check, same failure mode, cleaner
  commit message. Credited here fully; my variant exists only as a record
  of the independent derivation.

Patch published in the state I had it, for the audit trail.

## Notes

- `notes/copy-up-audit.md` — the full path walk and why the check must sit
  between stat and the copy itself
- affected: v5.11 .. v6.1 (everything since unprivileged overlay mounts)
