# One-Time Secret Service

A service that holds a piece of sensitive text for a recipient to read a limited number of times, then forgets it for good.

## Language

**Secret**:
The sensitive text a creator hands over, together with its expiry and view allowance.
_Avoid_: message, paste, note

**Share Token**:
The single opaque value in a share link that both locates a Secret and unlocks it; whoever holds it can read the Secret.
_Avoid_: id, link id, secret id

**Lookup ID**:
The part of a Share Token that locates a stored Secret; on its own it unlocks nothing.
_Avoid_: id, key

**Secret Key**:
The part of a Share Token that unlocks a stored Secret; it exists only in the Share Token, never in storage.
_Avoid_: password, passphrase, encryption key

**View**:
One successful read that returns a Secret's content; nothing else counts as a View.
_Avoid_: hit, access, open

**View Allowance**:
How many Views a Secret permits before it is gone; set by the creator as `max_views`.
_Avoid_: max views, read limit, view count

**Failed Unlock**:
A read that presents a Passphrase which does not unlock the Secret; it consumes no View, and the fifth one destroys the Secret.
_Avoid_: failed view, bad attempt, wrong password

**Deletion Token**:
A credential handed only to the creator at creation time that authorises Revoking that Secret; it is unrelated to, and not derivable from, the Share Token.
_Avoid_: delete key, revoke token, admin token

**Revoke**:
The creator's act of making a Secret Gone before its expiry or View Allowance would.
_Avoid_: delete, cancel, burn

**Gone**:
The single outward state of a Secret that is expired, out of Views, revoked or destroyed — indistinguishable from one that never existed.
_Avoid_: deleted, invalid, expired (as an umbrella term)

**Secret Ref**:
A one-way, per-process alias for a Secret used to correlate audit events; it cannot be turned back into a Lookup ID.
_Avoid_: secret id, log id

**Passphrase**:
An optional second factor the creator shares out of band; together with the Secret Key it unlocks the Secret, and it is never stored in any form.
_Avoid_: password, PIN
