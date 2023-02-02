# OverlayFS copy-up ownership walk (v6.1)

## The invariant that isn't

Copy-up is documented as "the mounter copies the file into the upper
layer." The implementation, however, only borrows the mounter's
*credentials* for the operation (`ovl_prepare_copy_up_creds`); the
*ownership* of the resulting upper dentry is taken verbatim from the
lower file's stat. When lower is a filesystem the mounter controls
(e.g. a user-namespaced FUSE mount), the stat contents are attacker
input.

## Walk

1. `ovl_copy_up_one()` → `ovl_getstat()` fills `ctx.stat` from the lower
   dentry. No mapping validation of `ctx.stat.uid/gid`.
2. `ovl_prepare_copy_up_creds()` switches to mounter creds.
3. VFS create with mounter creds, then ownership stamped from
   `ctx.stat` — an unmapped uid lands as the overflow id in the upper
   layer's view.
4. Setuid/capability bits survive copy-up by design (they are "file
   metadata"). The upper file is now a capability-bearing binary
   visible to a namespace where it appears owned by the overflow id —
   and executable.

## Why "just chown it away" doesn't save you

The overflow id *is* a valid file in the upper filesystem; the mapping
gap exists only between the two idspaces. Nothing in the copy-up path
refuses the operation, and by the time any user-visible uid exists the
capability-bearing file is already in the layer the victim reads.

## Fix shape

The check has to sit between (1) and (2): refuse when the stat owner
isn't mappable. Anything later is too late — the upper dentry may
already exist.
