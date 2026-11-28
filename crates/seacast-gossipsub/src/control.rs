//! The control strings (`seacast-bindings.md` §4, `seacast-lite.md` §2). Each
//! is one message id of a gossipsub control field:
//!
//! | field | string |
//! |---|---|
//! | IHAVE | offer: `"HAVE" 0x01 group(32) bitmap` |
//! | IDONTWANT | holding: `"HAVE" 0x04 group(32) flags(1) bitmap`, or version 1 |
//! | IWANT | `"WANT" 0x04 group(32) index(4 LE) flags(1) hops(1)`, or version 1 |
//! | IHAVE | mode: `"MODE" 0x01 flags(1)`, not in the specification |
//!
//! A holding and a WANT are written at version 4, an offer at version 1. Which
//! version to write where every extra field has its default is open in the
//! specification.

use seacast_core::{Bitmap, Bytes32, Have, MAX_BITMAP_BITS, MAX_HAVE_BYTES, Want};

use crate::payload::{MESSAGE_ID_BYTES, payload_group};

const HAVE_MAGIC: &[u8; 4] = b"HAVE";
#[cfg(feature = "pull-only")]
const MODE_MAGIC: &[u8; 4] = b"MODE";
const WANT_MAGIC: &[u8; 4] = b"WANT";
const V1: u8 = 1;
const V4: u8 = 4;

/// An offer's bytes before its bitmap: magic, version, group.
pub const OFFER_FIXED: usize = 4 + 1 + 32;
/// A holding's bytes before its bitmap: magic, version, group, flags.
pub const HOLDING_FIXED: usize = OFFER_FIXED + 1;
/// A WANT at version 4.
pub const WANT_BYTES: usize = OFFER_FIXED + 4 + 1 + 1;
/// A WANT at version 1 (`WantIndex`): no flags, no hops.
const WANT_V1_BYTES: usize = OFFER_FIXED + 4;
/// A mode: magic, version, flags.
#[cfg(feature = "pull-only")]
pub const MODE_BYTES: usize = 4 + 1 + 1;
/// The longest string written: a holding with a full bitmap.
pub const MAX_HAVE_STRING: usize = HOLDING_FIXED + MAX_HAVE_BYTES;

const CLAIM_ALL: u8 = 1;
const COMPLETE: u8 = 2;
const STANDING: u8 = 1;
const PROBE: u8 = 2;
#[cfg(feature = "pull-only")]
const PULL_ONLY: u8 = 1;

fn put_head(out: &mut [u8], magic: &[u8; 4], version: u8, group: &Bytes32) {
    out[..4].copy_from_slice(magic);
    out[4] = version;
    out[5..OFFER_FIXED].copy_from_slice(group);
}

fn put_bitmap(out: &mut [u8; MAX_HAVE_STRING], fixed: usize, bits: &Bitmap) -> usize {
    let bytes: &mut [u8; MAX_HAVE_BYTES] =
        (&mut out[fixed..fixed + MAX_HAVE_BYTES]).try_into().unwrap();
    fixed + bits.encode_to_slice(bytes)
}

/// Writes an offer's IHAVE string and returns its length.
pub fn offer_string(h: &Have, out: &mut [u8; MAX_HAVE_STRING]) -> usize {
    put_head(out, HAVE_MAGIC, V1, &h.group.key);
    put_bitmap(out, OFFER_FIXED, &h.bits)
}

/// Writes a holding's IDONTWANT string and returns its length.
pub fn holding_string(h: &Have, out: &mut [u8; MAX_HAVE_STRING]) -> usize {
    put_head(out, HAVE_MAGIC, V4, &h.group.key);
    out[OFFER_FIXED] = u8::from(h.claim_all) | u8::from(h.complete) << 1;
    put_bitmap(out, HOLDING_FIXED, &h.bits)
}

/// The IHAVE string by which a node tells a peer that it takes no chunk it
/// has not asked for (`pull_only`), or takes them again. Sent on each chunk
/// topic the peer joins.
#[cfg(feature = "pull-only")]
pub fn mode_string(pull_only: bool) -> [u8; MODE_BYTES] {
    let mut out = [0; MODE_BYTES];
    out[..4].copy_from_slice(MODE_MAGIC);
    out[4] = V1;
    out[5] = u8::from(pull_only) * PULL_ONLY;
    out
}

/// An IHAVE entry as a mode: whether its sender is pull only. A later
/// version is read for the flags it shares.
#[cfg(feature = "pull-only")]
pub fn read_mode(entry: &[u8]) -> Option<bool> {
    let entry: &[u8; MODE_BYTES] = entry.get(..MODE_BYTES)?.try_into().ok()?;
    (entry[..4] == *MODE_MAGIC && entry[4] >= V1).then_some(entry[5] & PULL_ONLY != 0)
}

/// The IWANT string of `w` for one index.
pub fn want_string(w: &Want, index: u32) -> [u8; WANT_BYTES] {
    let mut out = [0u8; WANT_BYTES];
    put_head(&mut out, WANT_MAGIC, V4, &w.group.key);
    out[OFFER_FIXED..OFFER_FIXED + 4].copy_from_slice(&index.to_le_bytes());
    out[OFFER_FIXED + 4] = u8::from(w.standing) | u8::from(w.probe) << 1;
    out[OFFER_FIXED + 5] = w.hops;
    out
}

/// The IWANT strings of `w`: one an index.
pub fn want_strings(w: &Want, mut put: impl FnMut(&[u8; WANT_BYTES])) {
    for index in w.bits.iter() {
        put(&want_string(w, index));
    }
}

/// Whether an IHAVE, IDONTWANT or IWANT entry is SEACAST's: one of the strings
/// by its magic, or of a chunk id's length. A length compare and a four-byte
/// compare: the host calls it on every entry and keeps the others for its own
/// gossipsub. `true` is no verdict on the entry: the readers below give it.
#[inline]
pub fn is_seacast(entry: &[u8]) -> bool {
    let mode = {
        #[cfg(feature = "pull-only")]
        {
            entry.len() >= MODE_BYTES && entry[..4] == *MODE_MAGIC
        }
        #[cfg(not(feature = "pull-only"))]
        {
            false
        }
    };
    entry.len() == MESSAGE_ID_BYTES ||
        entry.len() >= OFFER_FIXED && matches!(&entry[..4], b"HAVE" | b"WANT") ||
        mode
}

/// The group of a string that opens with `magic`, its version, and what
/// follows the group.
fn head<'a>(entry: &'a [u8], magic: &[u8; 4]) -> Option<(u8, Bytes32, &'a [u8])> {
    let (fixed, rest) = entry.split_at_checked(OFFER_FIXED)?;
    (fixed[..4] == *magic).then(|| (fixed[4], fixed[5..].try_into().unwrap(), rest))
}

/// An IHAVE entry as an offer: a version 1 `HaveBitmap`. Any other entry is
/// ignored without penalty, as one whose bitmap is longer than the node's.
pub fn read_offer(entry: &[u8]) -> Option<Have> {
    let (version, group, bits) = head(entry, HAVE_MAGIC)?;
    (version == V1).then_some(())?;
    Some(Have::offer(payload_group(group), Bitmap::from_wire_bytes(bits)?))
}

/// An IDONTWANT entry as a holding: a `HaveBitmap` of version 1, or of version
/// 4 with no reserved flag set. `None`: not a holding. Such an entry is an
/// opaque id ([`chunk_id_of`](crate::chunk_id_of)), or another topic's.
///
/// A version 1 holding carries no claims: `claim_all` and `complete` are clear
/// whatever its bitmap.
pub fn read_holding(entry: &[u8]) -> Option<Have> {
    let (version, group, rest) = head(entry, HAVE_MAGIC)?;
    let (flags, bits) = match version {
        V1 => (0, rest),
        V4 => {
            let (&flags, bits) = rest.split_first()?;
            (flags, bits)
        }
        _ => return None,
    };
    if flags & !(CLAIM_ALL | COMPLETE) != 0 {
        return None;
    }
    Some(Have::holding(
        payload_group(group),
        Bitmap::from_wire_bytes(bits)?,
        flags & CLAIM_ALL != 0,
        flags & COMPLETE != 0,
    ))
}

/// An IWANT entry as a WANT of one index. `None`, ignored without penalty: not
/// a WANT string, one of the wrong length, one with a reserved flag set, one
/// whose `hops` is over `route_hops` (the type's `ROUTE_HOPS`), or one whose
/// index is past the node's bitmaps. A version 1 `WantIndex` is read as a WANT
/// with every extra field clear.
pub fn read_want(entry: &[u8], route_hops: u8) -> Option<Want> {
    let (version, group, rest) = head(entry, WANT_MAGIC)?;
    let (flags, hops) = match (version, entry.len()) {
        (V1, WANT_V1_BYTES) => (0, 0),
        (V4, WANT_BYTES) => (rest[4], rest[5]),
        _ => return None,
    };
    let index = u32::from_le_bytes(rest[..4].try_into().unwrap());
    if flags & !(STANDING | PROBE) != 0 || hops > route_hops || index as usize >= MAX_BITMAP_BITS {
        return None;
    }
    Some(Want {
        standing: flags & STANDING != 0,
        probe: flags & PROBE != 0,
        hops,
        ..Want::direct(payload_group(group), Bitmap::singleton(index))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Bytes32 = [7; 32];

    #[test]
    fn test_want_bytes() {
        let want =
            Want { hops: 2, probe: true, ..Want::standing(payload_group(KEY), Bitmap::EMPTY) };
        let s = want_string(&want, 0x0102);
        assert_eq!(s.len(), 43);
        assert_eq!(&s[..5], b"WANT\x04");
        assert_eq!(s[5..37], KEY);
        assert_eq!(s[37..], [0x02, 0x01, 0, 0, 0b11, 2]);
        let read = read_want(&s, 2).unwrap();
        assert_eq!(read, Want { bits: Bitmap::singleton(0x0102), ..want });

        // Over the type's hops, a reserved flag, a wrong length: ignored.
        assert_eq!(read_want(&s, 1), None);
        let mut reserved = s;
        reserved[41] |= 4;
        assert_eq!(read_want(&reserved, 2), None);
        assert_eq!(read_want(&s[..42], 2), None);
        let mut long = s.to_vec();
        long.push(0);
        assert_eq!(read_want(&long, 2), None);
        let mut far = s;
        far[37..41].copy_from_slice(&(MAX_BITMAP_BITS as u32).to_le_bytes());
        assert_eq!(read_want(&far, 2), None);

        // Version 1: the index alone.
        let mut v1 = s[..41].to_vec();
        v1[4] = 1;
        let plain = Want::direct(payload_group(KEY), Bitmap::singleton(0x0102));
        assert_eq!(read_want(&v1, 0), Some(plain));
        v1.push(0);
        assert_eq!(read_want(&v1, 0), None);

        let mut all = Vec::new();
        want_strings(&Want::direct(payload_group(KEY), Bitmap::from_indices([1, 9])), |s| {
            all.push(u32::from_le_bytes(s[37..41].try_into().unwrap()))
        });
        assert_eq!(all, [1, 9]);
    }

    #[test]
    fn test_is_seacast() {
        let mut out = [0u8; MAX_HAVE_STRING];
        let len = offer_string(&Have::offer(payload_group(KEY), Bitmap::EMPTY), &mut out);
        assert!(is_seacast(&out[..len]));
        assert!(is_seacast(&want_string(&Want::direct(payload_group(KEY), Bitmap::EMPTY), 0)));
        // A chunk's id, by its length; a stock id and a string cut short are not.
        assert!(is_seacast(&[0u8; MESSAGE_ID_BYTES]));
        assert!(!is_seacast(&[0u8; 20]));
        assert!(!is_seacast(&out[..len - 1]));
        assert!(!is_seacast(b"HAVE"));
        assert!(!is_seacast(&[]));
    }

    #[cfg(feature = "pull-only")]
    #[test]
    fn test_mode_bytes() {
        for pull_only in [true, false] {
            let entry = mode_string(pull_only);
            assert_eq!(&entry, &[b'M', b'O', b'D', b'E', 1, u8::from(pull_only)]);
            assert!(is_seacast(&entry));
            assert_eq!(read_mode(&entry), Some(pull_only));
            assert_eq!(read_offer(&entry), None);
        }
        assert_eq!(read_mode(b"MODE\x01"), None);
        assert_eq!(read_mode(b"MODE\x00\x01"), None);
    }

    #[test]
    fn test_have_bytes() {
        let bits = Bitmap::from_indices([0, 9]);
        let mut out = [0u8; MAX_HAVE_STRING];

        let offer = Have::offer(payload_group(KEY), bits);
        let len = offer_string(&offer, &mut out);
        assert_eq!(&out[..5], b"HAVE\x01");
        assert_eq!(out[5..37], KEY);
        assert_eq!(out[37..len], [0b1, 0b10]);
        assert_eq!(read_offer(&out[..len]), Some(offer));
        // In an IDONTWANT the same string is a holding with no claims.
        let plain = Have::holding(payload_group(KEY), bits, false, false);
        assert_eq!(read_holding(&out[..len]), Some(plain));

        let holding = Have::holding(payload_group(KEY), bits, true, true);
        let len = holding_string(&holding, &mut out);
        assert_eq!(&out[..5], b"HAVE\x04");
        assert_eq!(out[37..len], [0b11, 0b1, 0b10]);
        assert_eq!(read_holding(&out[..len]), Some(holding));
        // Version 4 is no offer.
        assert_eq!(read_offer(&out[..len]), None);

        // A reserved flag, a string cut short, another version, another id.
        let mut reserved = out;
        reserved[37] |= 4;
        assert_eq!(read_holding(&reserved[..len]), None);
        assert_eq!(read_holding(&out[..37]), None);
        assert_eq!(read_holding(&out[..36]), None);
        let mut other = out;
        other[4] = 2;
        assert_eq!(read_holding(&other[..len]), None);
        assert_eq!(read_holding(&[0u8; 20]), None);
        assert_eq!(read_offer(&[0u8; 56]), None);

        // An empty bitmap, and one longer than the node's.
        let empty = Have::holding(payload_group(KEY), Bitmap::EMPTY, false, true);
        let len = holding_string(&empty, &mut out);
        assert_eq!(len, HOLDING_FIXED);
        assert_eq!(read_holding(&out[..len]), Some(empty));
        let mut long = out[..HOLDING_FIXED].to_vec();
        long.resize(HOLDING_FIXED + MAX_HAVE_BYTES + 1, 0xff);
        assert_eq!(read_holding(&long), None);
    }
}
