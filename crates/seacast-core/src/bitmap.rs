use std::{
    fmt,
    ops::{BitAnd, BitOr, BitOrAssign, Not},
};

/// Maximum number of chunks in a coded group (`seacast-lite.md` §1 `[c6]`).
pub const MAX_CHUNKS: usize = 256;

/// Number of `u64` words in a stack-allocated [`Bitmap`]: the indices a group
/// may have, 64 a word. `seacast-lite.md` §8.3 allows 8192
/// (`MAX_PLAIN_CHUNKS`); every table, message and queue item that holds a
/// bitmap grows with this, so it is set to what an object of 10 MiB needs, and
/// a group or an index past it is refused.
pub const BITMAP_WORDS: usize = 16;

/// Maximum bit index representable explicitly in [`Bitmap`].
pub const MAX_BITMAP_BITS: usize = BITMAP_WORDS * 64;

/// Maximum bytes in a wire `Have` bitmap.
pub const MAX_HAVE_BYTES: usize = BITMAP_WORDS * 8;

/// A fixed-size, stack-allocated (`Copy`) chunk index bitmap with support for
/// complemented (all-ones / `EVERY_INDEX`) representations, matching the
/// two's-complement bitset semantics of `seacast.md` with **zero heap
/// allocation**.
///
/// - When `inverted == false`, `words` stores the set bits (`0` beyond
///   `MAX_BITMAP_BITS`).
/// - When `inverted == true`, `words` stores the cleared bits (`1` beyond
///   `MAX_BITMAP_BITS`).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bitmap {
    inverted: bool,
    words: [u64; BITMAP_WORDS],
}

static EMPTY_BITMAP: Bitmap = Bitmap::EMPTY;

impl Default for Bitmap {
    #[inline]
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Bitmap {
    /// Empty bitmap (`EMPTY` in `seacast.md`).
    pub const EMPTY: Self = Self { inverted: false, words: [0u64; BITMAP_WORDS] };

    /// Infinite all-ones bitmap (`EVERY_INDEX` in `seacast.md`).
    pub const EVERY_INDEX: Self = Self { inverted: true, words: [0u64; BITMAP_WORDS] };

    /// The representation: whether the words hold the cleared bits, and the
    /// words.
    #[inline]
    pub(crate) const fn raw(&self) -> (bool, &[u64; BITMAP_WORDS]) {
        (self.inverted, &self.words)
    }

    #[inline]
    pub(crate) const fn from_raw(inverted: bool, words: [u64; BITMAP_WORDS]) -> Self {
        Self { inverted, words }
    }

    /// Returns a `'static` reference to an empty bitmap.
    #[inline]
    pub const fn empty_ref() -> &'static Self {
        &EMPTY_BITMAP
    }

    /// Creates an empty bitmap.
    #[inline]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// Creates a bitmap with bits `0..n` set (`all_bits(n)` in
    /// `seacast-lite.md`).
    #[inline]
    pub fn all_bits(n: u32) -> Self {
        let n = (n as usize).min(MAX_BITMAP_BITS);
        if n == 0 {
            return Self::EMPTY;
        }
        let full_words = n / 64;
        let rem_bits = n % 64;
        let mut words = [0u64; BITMAP_WORDS];
        let mut i = 0;
        while i < full_words {
            words[i] = u64::MAX;
            i += 1;
        }
        if rem_bits > 0 && full_words < BITMAP_WORDS {
            words[full_words] = (1u64 << rem_bits) - 1;
        }
        Self { inverted: false, words }
    }

    /// Creates a bitmap with a single index set (`bitmap({i})` in
    /// `seacast-lite.md`).
    #[inline]
    pub fn singleton(index: u32) -> Self {
        let mut b = Self::EMPTY;
        b.set(index);
        b
    }

    /// Creates a bitmap from an iterator of bit indices.
    #[inline]
    pub fn from_indices<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        let mut b = Self::EMPTY;
        for idx in iter {
            b.set(idx);
        }
        b
    }

    /// Returns `true` if this bitmap is complemented (infinite all-ones beyond
    /// `MAX_BITMAP_BITS`).
    #[inline]
    pub const fn is_unbounded(&self) -> bool {
        self.inverted
    }

    /// Returns `true` if no bits are set.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        if self.inverted {
            return false;
        }
        let mut i = 0;
        while i < BITMAP_WORDS {
            if self.words[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Returns `true` if `index` is set (`has(bits, i)` in `seacast-lite.md`).
    #[inline]
    pub const fn has(&self, index: u32) -> bool {
        let word_idx = (index as usize) / 64;
        let bit_idx = (index as usize) % 64;
        let in_words = if word_idx < BITMAP_WORDS {
            (self.words[word_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        };
        if self.inverted { !in_words } else { in_words }
    }

    /// Sets `index` to `1`.
    #[inline]
    pub fn set(&mut self, index: u32) {
        let word_idx = (index as usize) / 64;
        let bit_idx = (index as usize) % 64;
        assert!(word_idx < BITMAP_WORDS, "bitmap index out of bounds");
        if self.inverted {
            self.words[word_idx] &= !(1u64 << bit_idx);
        } else {
            self.words[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Clears `index` to `0`.
    #[inline]
    pub fn clear(&mut self, index: u32) {
        let word_idx = (index as usize) / 64;
        let bit_idx = (index as usize) % 64;
        if word_idx >= BITMAP_WORDS {
            return;
        }
        if self.inverted {
            self.words[word_idx] |= 1u64 << bit_idx;
        } else {
            self.words[word_idx] &= !(1u64 << bit_idx);
        }
    }

    /// Returns the number of set bits (`popcount(bits)` in `seacast-lite.md`).
    /// Panics if called on an unbounded complemented bitmap (`EVERY_INDEX`).
    #[inline]
    pub const fn popcount(&self) -> u32 {
        assert!(!self.inverted, "popcount called on unbounded complemented Bitmap");
        let mut total = 0u32;
        let mut i = 0;
        while i < BITMAP_WORDS {
            total += self.words[i].count_ones();
            i += 1;
        }
        total
    }

    /// Computes `self & !other` without intermediate allocation.
    #[inline]
    pub const fn and_not(&self, other: &Self) -> Self {
        self.bitand_const(&other.not_const())
    }

    /// Returns the lowest set bit index if non-empty.
    #[inline]
    pub const fn first_index(&self) -> Option<u32> {
        if self.inverted {
            let mut w_idx = 0;
            while w_idx < BITMAP_WORDS {
                let inv_w = !self.words[w_idx];
                if inv_w != 0 {
                    return Some((w_idx as u32) * 64 + inv_w.trailing_zeros());
                }
                w_idx += 1;
            }
            return Some(MAX_BITMAP_BITS as u32);
        }
        let mut w_idx = 0;
        while w_idx < BITMAP_WORDS {
            let w = self.words[w_idx];
            if w != 0 {
                return Some((w_idx as u32) * 64 + w.trailing_zeros());
            }
            w_idx += 1;
        }
        None
    }

    /// Returns `true` if all set bits are `< n` (`all_below(bits, n)`).
    #[inline]
    pub fn all_below(&self, n: u32) -> bool {
        if self.inverted {
            return false;
        }
        self.and_not(&Self::all_bits(n)).is_empty()
    }

    /// Returns the stripped little-endian wire byte length of this bitmap.
    #[inline]
    pub const fn wire_byte_len(&self) -> usize {
        if self.inverted {
            return usize::MAX;
        }
        let mut len = 0usize;
        let mut w_idx = 0;
        while w_idx < BITMAP_WORDS {
            let w = self.words[w_idx];
            if w != 0 {
                let nz_bytes = 8 - (w.leading_zeros() as usize / 8);
                len = w_idx * 8 + nz_bytes;
            }
            w_idx += 1;
        }
        len
    }

    /// Iterates over all set bit indices in ascending order with zero heap
    /// allocation. Panics if called on an unbounded complemented bitmap.
    #[inline]
    pub fn iter(&self) -> BitmapIter {
        assert!(!self.inverted, "iter() called on unbounded complemented Bitmap");
        BitmapIter { words: self.words, word_idx: 0, current_word: self.words[0] }
    }

    /// Encodes a finite bitmap into `out` (little-endian bytes, trailing zero
    /// bytes stripped) and returns the number of bytes written
    /// (`0..=MAX_HAVE_BYTES`).
    pub fn encode_to_slice(&self, out: &mut [u8; MAX_HAVE_BYTES]) -> usize {
        assert!(!self.inverted, "cannot wire-encode unbounded complemented Bitmap");
        let mut len = 0usize;
        for (w_idx, &w) in self.words.iter().enumerate() {
            let wb = w.to_le_bytes();
            out[w_idx * 8..(w_idx + 1) * 8].copy_from_slice(&wb);
            if w != 0 {
                let nz_bytes = 8 - (w.leading_zeros() as usize / 8);
                len = w_idx * 8 + nz_bytes;
            }
        }
        len
    }

    /// Decodes a bitmap from little-endian wire bytes.
    pub fn from_wire_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_HAVE_BYTES {
            return None;
        }
        let mut words = [0u64; BITMAP_WORDS];
        for (w_idx, chunk) in bytes.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            words[w_idx] = u64::from_le_bytes(buf);
        }
        Some(Self { inverted: false, words })
    }

    #[inline]
    const fn not_const(&self) -> Self {
        Self { inverted: !self.inverted, words: self.words }
    }

    #[inline]
    const fn bitand_const(&self, rhs: &Self) -> Self {
        let mut words = [0u64; BITMAP_WORDS];
        let mut i = 0;
        match (self.inverted, rhs.inverted) {
            (false, false) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] & rhs.words[i];
                    i += 1;
                }
                Self { inverted: false, words }
            }
            (false, true) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] & !rhs.words[i];
                    i += 1;
                }
                Self { inverted: false, words }
            }
            (true, false) => {
                while i < BITMAP_WORDS {
                    words[i] = rhs.words[i] & !self.words[i];
                    i += 1;
                }
                Self { inverted: false, words }
            }
            (true, true) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] | rhs.words[i];
                    i += 1;
                }
                Self { inverted: true, words }
            }
        }
    }

    #[inline]
    const fn bitor_const(&self, rhs: &Self) -> Self {
        let mut words = [0u64; BITMAP_WORDS];
        let mut i = 0;
        match (self.inverted, rhs.inverted) {
            (false, false) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] | rhs.words[i];
                    i += 1;
                }
                Self { inverted: false, words }
            }
            (false, true) => {
                while i < BITMAP_WORDS {
                    words[i] = rhs.words[i] & !self.words[i];
                    i += 1;
                }
                Self { inverted: true, words }
            }
            (true, false) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] & !rhs.words[i];
                    i += 1;
                }
                Self { inverted: true, words }
            }
            (true, true) => {
                while i < BITMAP_WORDS {
                    words[i] = self.words[i] & rhs.words[i];
                    i += 1;
                }
                Self { inverted: true, words }
            }
        }
    }
}

impl Not for Bitmap {
    type Output = Bitmap;

    #[inline]
    fn not(self) -> Self::Output {
        self.not_const()
    }
}

impl Not for &Bitmap {
    type Output = Bitmap;

    #[inline]
    fn not(self) -> Self::Output {
        self.not_const()
    }
}

impl BitAnd for Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand_const(&rhs)
    }
}

impl BitAnd for &Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        self.bitand_const(rhs)
    }
}

impl BitAnd<&Bitmap> for Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitand(self, rhs: &Bitmap) -> Self::Output {
        self.bitand_const(rhs)
    }
}

impl BitOr for Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor_const(&rhs)
    }
}

impl BitOr for &Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        self.bitor_const(rhs)
    }
}

impl BitOr<&Bitmap> for Bitmap {
    type Output = Bitmap;

    #[inline]
    fn bitor(self, rhs: &Bitmap) -> Self::Output {
        self.bitor_const(rhs)
    }
}

impl BitOrAssign for Bitmap {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.bitor_const(&rhs);
    }
}

impl BitOrAssign<&Bitmap> for Bitmap {
    #[inline]
    fn bitor_assign(&mut self, rhs: &Bitmap) {
        *self = self.bitor_const(rhs);
    }
}

impl fmt::Debug for Bitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.inverted {
            write!(f, "Bitmap(~[")?;
            let mut first = true;
            for (w_idx, &w) in self.words.iter().enumerate() {
                let mut cur = w;
                while cur != 0 {
                    let tz = cur.trailing_zeros() as usize;
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", w_idx * 64 + tz)?;
                    first = false;
                    cur &= cur - 1;
                }
            }
            write!(f, "])")
        } else {
            write!(f, "Bitmap([")?;
            let mut first = true;
            for idx in self.iter() {
                if !first {
                    write!(f, ", ")?;
                }
                write!(f, "{}", idx)?;
                first = false;
            }
            write!(f, "])")
        }
    }
}

/// Zero-allocation iterator over set bit indices in a finite [`Bitmap`].
#[derive(Clone)]
pub struct BitmapIter {
    words: [u64; BITMAP_WORDS],
    word_idx: usize,
    current_word: u64,
}

impl Iterator for BitmapIter {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.current_word == 0 {
            self.word_idx += 1;
            if self.word_idx >= BITMAP_WORDS {
                return None;
            }
            self.current_word = self.words[self.word_idx];
        }
        let tz = self.current_word.trailing_zeros();
        self.current_word &= self.current_word - 1;
        Some((self.word_idx as u32) * 64 + tz)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_operations() {
        let a = Bitmap::all_bits(130);
        assert_eq!(a.popcount(), 130);
        assert!(a.has(0));
        assert!(a.has(64));
        assert!(a.has(129));
        assert!(!a.has(130));

        let b = Bitmap::singleton(64) | Bitmap::singleton(300);
        assert_eq!(b.popcount(), 2);

        let diff = a.and_not(&b);
        assert_eq!(diff.popcount(), 129);
        assert!(!diff.has(64));

        // Complemented bitmap semantics (`EVERY_INDEX & a == a`)
        let every = Bitmap::EVERY_INDEX;
        assert!(every.has(9999));
        let masked = every & a;
        assert_eq!(masked, a);

        let not_b = !b;
        assert!(!not_b.has(64));
        assert!(!not_b.has(300));
        assert!(not_b.has(65));
        assert_eq!(a & not_b, diff);

        // Wire roundtrip without heap allocation
        let mut wire = [0u8; MAX_HAVE_BYTES];
        let len = b.encode_to_slice(&mut wire);
        let decoded = Bitmap::from_wire_bytes(&wire[..len]).unwrap();
        assert_eq!(decoded, b);
    }
}
