//! Systematic Reed–Solomon codec over `GF(2^8)` with primitive polynomial
//! `0x11d` (`x^8 + x^4 + x^3 + x^2 + 1`) and evaluation points `0..N-1`
//! (`seacast-lite.md` §1 `[c6]`).
//!
//! Encoding and decoding are both "each output segment is a fixed combination
//! of input segments" ([`combine`]). The combination of one stretch of one
//! output is the [`Kernel`], chosen once from what the CPU has: [`gfni`],
//! [`avx2`], [`neon`] or [`portable`]. The parity of a `(K, 2K)` code with `K`
//! a power of two has a second path, [`fft`], which gives the same bytes.
//!
//! A code of more than [`MAX_NARROW_CHUNKS`] chunks is over `GF(2^16)`
//! ([`gf16`]), with segments of whole blocks of [`WIDE_BLOCK`] bytes: every
//! function here takes either.

use std::sync::{LazyLock, OnceLock};

/// Calls `$check::<K>()` for every kernel the CPU has instructions for.
#[cfg(test)]
macro_rules! each_kernel {
    ($check:ident) => {{
        use crate::reed_solomon::portable::Portable;
        $check::<Portable>();
        #[cfg(target_arch = "x86_64")]
        {
            use crate::reed_solomon::{Kernel, avx2::Avx2, gfni::Gfni};
            if Avx2::supported() {
                $check::<Avx2>();
            }
            if Gfni::supported() {
                $check::<Gfni>();
            }
        }
        #[cfg(target_arch = "aarch64")]
        $check::<crate::reed_solomon::neon::Neon>();
    }};
}

#[cfg(target_arch = "x86_64")]
mod avx2;
mod fft;
#[allow(dead_code)]
mod gf16;
#[cfg(target_arch = "x86_64")]
mod gfni;
#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(any(test, not(target_arch = "aarch64")))]
mod portable;

/// The combination of one stretch of bytes, for one set of instructions. A
/// kernel is used only where [`Kernel::supported`] holds.
trait Kernel: Copy + 'static {
    /// A constant in the form the kernel multiplies by.
    type Coeff: Copy + Send + Sync + 'static;

    /// Twice the parity rows, for each level of the transform, from which
    /// [`fft`] is ahead of the matrix: more where the matrix takes several rows
    /// a pass.
    const FFT_FROM_HALF_ROWS: usize;

    /// Whether [`combine`] copies a strip of the sources side by side before it
    /// reads them: where a row is a pass over them. A kernel that takes several
    /// rows a pass reads them too few times to gain.
    const GATHER: bool;

    fn supported() -> bool;
    fn caches() -> &'static Caches<Self>;

    fn coeff(c: u8) -> Self::Coeff;
    /// The map linear over `GF(2)` that takes bit `j` of a byte to `images[j]`,
    /// in place of a product.
    fn linear(images: [u8; 8]) -> Self::Coeff;

    /// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]` over the bytes the kernel
    /// takes. Returns the bytes written, the caller's to finish.
    fn row(coeffs: &[Self::Coeff], srcs: &[&[u8]], at: usize, dst: &mut [u8]) -> usize;

    /// [`Kernel::row`] for `G` rows at once, row `g` with the coefficients
    /// `coeffs[g * cols..][..cols]`: from `from` of the sources to `at` of the
    /// destinations, `len` bytes. Returns the bytes written of each: none where
    /// the kernel takes a row a pass.
    fn rows<const G: usize>(
        _coeffs: &[Self::Coeff],
        _srcs: &[&[u8]],
        _from: usize,
        _at: usize,
        _len: usize,
        _dsts: &mut [&mut [u8]],
    ) -> usize {
        0
    }

    /// `h ^= g`.
    fn xor(g: &[u8], h: &mut [u8]);

    /// `g ^= c * h`, then `h ^= g`. Returns the bytes done.
    fn butterfly(c: &Self::Coeff, g: &mut [u8], h: &mut [u8]) -> usize;
    /// `h ^= g`, then `g ^= c * h`.
    fn butterfly_back(c: &Self::Coeff, g: &mut [u8], h: &mut [u8]) -> usize;
    /// [`Kernel::butterfly`] over the two planes of `GF(2^16)` symbols.
    fn butterfly2(
        c: &[Self::Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize;
    fn butterfly2_back(
        c: &[Self::Coeff; 4],
        g0: &mut [u8],
        g1: &mut [u8],
        h0: &mut [u8],
        h1: &mut [u8],
    ) -> usize;
}

/// What is built once for a kernel, in its form of a constant.
struct Caches<K: Kernel> {
    /// [`parity_matrix`] of `(k, 2k)`, the one shape the protocol codes with.
    parity: [OnceLock<Matrix<K>>; 129],
    wide: LazyLock<gf16::Tables<K>>,
}

impl<K: Kernel> Caches<K> {
    const fn new() -> Self {
        Self { parity: [const { OnceLock::new() }; 129], wide: LazyLock::new(gf16::Tables::new) }
    }
}

/// The codec over the kernel the CPU has instructions for, chosen once.
#[allow(clippy::type_complexity)]
struct Code {
    parity_rows: fn(&[&[u8]], usize, &[usize], &mut [&mut [u8]]),
    reconstruct_into: fn(usize, usize, &[u32], &[&[u8]], &mut [u8]) -> Option<()>,
    complete_data_in_place:
        fn(usize, usize, &mut [u8], &[u8], &dyn Fn(usize) -> bool) -> Option<()>,
    invert: fn(usize, &[u8]) -> Option<Vec<u8>>,
}

impl Code {
    fn of<K: Kernel>() -> Self {
        assert!(K::supported());
        Self {
            parity_rows: parity_rows::<K>,
            reconstruct_into: reconstruct_into::<K>,
            complete_data_in_place: complete_data_in_place::<K>,
            invert: invert::<K>,
        }
    }

    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if gfni::Gfni::supported() {
                return Self::of::<gfni::Gfni>();
            }
            if avx2::Avx2::supported() {
                return Self::of::<avx2::Avx2>();
            }
        }
        #[cfg(target_arch = "aarch64")]
        return Self::of::<neon::Neon>();
        #[cfg(not(target_arch = "aarch64"))]
        Self::of::<portable::Portable>()
    }
}

static CODE: LazyLock<Code> = LazyLock::new(Code::detect);

const POLY: u16 = 0x11d;

/// The most chunks of a code over `GF(2^8)`: its points. A longer code is over
/// `GF(2^16)`.
pub const MAX_NARROW_CHUNKS: usize = 256;

/// The most chunks of a code.
pub const MAX_WIDE_CHUNKS: usize = gf16::MAX_CHUNKS;

/// A segment of a code over `GF(2^16)` is whole blocks of this many bytes.
pub const WIDE_BLOCK: usize = gf16::BLOCK;

/// Lookup tables for `GF(2^8)` multiplication and inversion.
pub struct Gf256Tables {
    exp: [u8; 512],
    log: [u8; 256],
    inv: [u8; 256],
}

impl Default for Gf256Tables {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf256Tables {
    pub const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut inv = [0u8; 256];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= POLY;
            }
            i += 1;
        }
        exp[510] = exp[0];
        exp[511] = exp[1];
        let mut a = 1;
        while a < 256 {
            let l = log[a] as usize;
            inv[a] = exp[255 - l];
            a += 1;
        }
        Self { exp, log, inv }
    }

    #[inline]
    pub const fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let idx = (self.log[a as usize] as usize) + (self.log[b as usize] as usize);
            self.exp[idx]
        }
    }

    #[inline]
    pub const fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "division by zero in GF(2^8)");
        self.inv[a as usize]
    }

    #[inline]
    pub const fn pow(&self, a: u8, p: usize) -> u8 {
        if p == 0 {
            1
        } else if a == 0 {
            0
        } else {
            let l = (self.log[a as usize] as usize * p) % 255;
            self.exp[l]
        }
    }
}

const TABLES: Gf256Tables = Gf256Tables::new();

pub static GF256: Gf256Tables = TABLES;

/// Every product: row `a` is multiplication by `a`.
static MUL: [[u8; 256]; 256] = {
    let mut out = [[0u8; 256]; 256];
    let mut a = 0;
    while a < 256 {
        let mut b = 0;
        while b < 256 {
            out[a][b] = TABLES.mul(a as u8, b as u8);
            b += 1;
        }
        a += 1;
    }
    out
};

/// The products of `c` with the sixteen low nibbles, then with the sixteen high
/// ones: a product is the sum of one of each.
#[allow(dead_code)]
fn nibble_tables(c: u8) -> [u8; 32] {
    let products = &MUL[c as usize];
    std::array::from_fn(|i| if i < 16 { products[i] } else { products[(i - 16) << 4] })
}

/// [`nibble_tables`] of the map linear over `GF(2)` that takes bit `j` of a
/// byte to `images[j]`.
#[allow(dead_code)]
fn linear_tables(images: [u8; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for x in 1..16usize {
        let (rest, bit) = (x & (x - 1), x.trailing_zeros() as usize);
        out[x] = out[rest] ^ images[bit];
        out[16 + x] = out[16 + rest] ^ images[4 + bit];
    }
    out
}

/// `dst[i] = sum_j coeffs[j] * srcs[j][at + i]`, a byte at a time: the
/// reference for the kernels, and what finishes the bytes past their last whole
/// vector.
fn scalar_row(coeffs: &[u8], srcs: &[&[u8]], at: usize, dst: &mut [u8]) {
    dst.fill(0);
    for (&c, src) in coeffs.iter().zip(srcs) {
        let products = &MUL[c as usize];
        for (d, &s) in dst.iter_mut().zip(&src[at..]) {
            *d ^= products[s as usize];
        }
    }
}

/// Bytes of every segment combined before moving on: a stretch of all the
/// inputs is read once per output, so it has to stay in cache across them.
/// Whole vectors of every kernel.
const STRIP: usize = 1024;

/// A matrix of `GF(2^8)` constants, row-major, with each in the form the kernel
/// multiplies by.
struct Matrix<K: Kernel> {
    cols: usize,
    bytes: Vec<u8>,
    coeffs: Vec<K::Coeff>,
}

impl<K: Kernel> Matrix<K> {
    fn new(cols: usize, bytes: Vec<u8>) -> Self {
        let coeffs = bytes.iter().map(|&c| K::coeff(c)).collect();
        Self { cols, bytes, coeffs }
    }

    fn row(&self, r: usize) -> &[u8] {
        &self.bytes[r * self.cols..][..self.cols]
    }
}

/// `dsts[r] = sum_j m[r][j] * srcs[j]`, every segment the same length.
fn combine<K: Kernel>(m: &Matrix<K>, srcs: &[&[u8]], dsts: &mut [&mut [u8]]) {
    let Some(size) = dsts.first().map(|dst| dst.len()) else {
        return;
    };
    assert_eq!(srcs.len(), m.cols);
    assert_eq!(dsts.len() * m.cols, m.bytes.len());
    assert!(srcs.iter().all(|src| src.len() == size) && dsts.iter().all(|dst| dst.len() == size));
    // Segments of one buffer lie a multiple of the cache's way apart, or nearly,
    // and a strip of each then falls in the same few sets. Read once per
    // row, they evict each other; copied side by side first, they do not.
    let gather = K::GATHER && dsts.len() > 2;
    let mut work = vec![0u8; if gather { m.cols * STRIP } else { 0 }];
    for at in (0..size).step_by(STRIP) {
        let end = (at + STRIP).min(size);
        let gathered: Vec<&[u8]>;
        let (srcs, from) = if gather {
            let slots = work.as_chunks_mut::<STRIP>().0;
            for (slot, src) in slots.iter_mut().zip(srcs) {
                slot[..end - at].copy_from_slice(&src[at..end]);
            }
            gathered = slots.iter().map(|slot| &slot[..]).collect();
            (&gathered[..], 0)
        } else {
            (srcs, at)
        };
        let grouped = grouped_rows(m, srcs, from, at, end, dsts);
        for (r, dst) in dsts.iter_mut().enumerate().skip(grouped) {
            let dst = &mut dst[at..end];
            let done = K::row(&m.coeffs[r * m.cols..][..m.cols], srcs, from, dst);
            scalar_row(m.row(r), srcs, from + done, &mut dst[done..]);
        }
    }
}

/// [`combine`] over `at..end` of every destination, from `from` of every
/// source, by the kernel that takes several rows a pass: eight while there
/// are, then four, then two. Returns the rows done: the rest are the caller's.
fn grouped_rows<K: Kernel>(
    m: &Matrix<K>,
    srcs: &[&[u8]],
    from: usize,
    at: usize,
    end: usize,
    dsts: &mut [&mut [u8]],
) -> usize {
    let mut r = 0;
    for size in [8, 4, 2] {
        while r + size <= dsts.len() {
            let group = &mut dsts[r..r + size];
            let coeffs = &m.coeffs[r * m.cols..][..size * m.cols];
            let done = match size {
                8 => K::rows::<8>(coeffs, srcs, from, at, end - at, group),
                4 => K::rows::<4>(coeffs, srcs, from, at, end - at, group),
                _ => K::rows::<2>(coeffs, srcs, from, at, end - at, group),
            };
            // What is left of the strip, a row at a time.
            for (g, dst) in group.iter_mut().enumerate() {
                let (from, dst) = (from + done, &mut dst[at + done..end]);
                let done = K::row(&m.coeffs[(r + g) * m.cols..][..m.cols], srcs, from, dst);
                scalar_row(m.row(r + g), srcs, from + done, &mut dst[done..]);
            }
            r += size;
        }
    }
    r
}

/// Rows `k..n` of the systematic generator over the points `0..n`: row `r`
/// holds the Lagrange basis polynomials of the points `0..k`, evaluated at `r`.
/// Addition being XOR, the difference of two points is their XOR.
fn parity_bytes(k: usize, n: usize) -> Vec<u8> {
    assert!(k >= 1 && k <= n && n <= 256);
    let product = |r: usize, skip: usize| {
        (0..k).filter(|&j| j != skip).fold(1u8, |acc, j| GF256.mul(acc, (r ^ j) as u8))
    };
    let denominators: Vec<u8> = (0..k).map(|c| GF256.inv(product(c, c))).collect();
    let mut bytes = Vec::with_capacity((n - k) * k);
    for r in k..n {
        // No factor is zero: `r` is none of the points.
        let all = product(r, usize::MAX);
        bytes.extend(
            (0..k).map(|c| GF256.mul(GF256.mul(all, GF256.inv((r ^ c) as u8)), denominators[c])),
        );
    }
    bytes
}

fn parity_matrix<K: Kernel>(k: usize, n: usize) -> Matrix<K> {
    Matrix::new(k, parity_bytes(k, n))
}

/// The parity matrix of `(k, n)`: borrowed from the cache when it is there.
enum Parity<K: Kernel> {
    Cached(&'static Matrix<K>),
    Built(Matrix<K>),
}

impl<K: Kernel> std::ops::Deref for Parity<K> {
    type Target = Matrix<K>;

    fn deref(&self) -> &Matrix<K> {
        match self {
            Parity::Cached(m) => m,
            Parity::Built(m) => m,
        }
    }
}

fn parity_of<K: Kernel>(k: usize, n: usize) -> Parity<K> {
    if n == 2 * k {
        Parity::Cached(K::caches().parity[k].get_or_init(|| parity_matrix(k, n)))
    } else {
        Parity::Built(parity_matrix(k, n))
    }
}

/// Builds the `n x k` systematic generator matrix over evaluation points
/// `0..n-1`.
///
/// The top `k x k` submatrix is the identity matrix, and the bottom `(n - k) x
/// k` submatrix is the parity encoding matrix `V_parity * V_data^{-1}`.
pub fn build_systematic_matrix(k: usize, n: usize) -> Vec<Vec<u8>> {
    let parity = parity_bytes(k, n);
    let identity = (0..k).map(|r| (0..k).map(|c| u8::from(r == c)).collect());
    identity.chain(parity.chunks_exact(k).map(<[u8]>::to_vec)).collect()
}

/// The inverse of the `size x size` matrix `a`, row-major, by Gauss–Jordan
/// elimination, if it has one.
fn invert<K: Kernel>(size: usize, a: &[u8]) -> Option<Vec<u8>> {
    assert_eq!(a.len(), size * size);
    // `[a | identity]`, reduced until it is `[identity | inverse]`.
    let width = 2 * size;
    let mut rows = vec![0u8; size * width];
    for (r, row) in rows.chunks_exact_mut(width).enumerate() {
        row[..size].copy_from_slice(&a[r * size..][..size]);
        row[size + r] = 1;
    }
    let mut pivot_row = vec![0u8; width];
    let mut updated = vec![0u8; width];
    for col in 0..size {
        let pivot = (col..size).find(|&r| rows[r * width + col] != 0)?;
        if pivot != col {
            let (upper, lower) = rows.split_at_mut(pivot * width);
            upper[col * width..][..width].swap_with_slice(&mut lower[..width]);
        }
        let scale = GF256.inv(rows[col * width + col]);
        for (out, &byte) in pivot_row.iter_mut().zip(&rows[col * width..][..width]) {
            *out = MUL[scale as usize][byte as usize];
        }
        rows[col * width..][..width].copy_from_slice(&pivot_row);
        for (r, row) in rows.chunks_exact_mut(width).enumerate() {
            let factor = row[col];
            if r == col || factor == 0 {
                continue;
            }
            // `row += factor * pivot_row`, through the kernel, which cannot write a source.
            let coeffs = [K::coeff(1), K::coeff(factor)];
            let srcs = [&row[..], &pivot_row[..]];
            let done = K::row(&coeffs, &srcs, 0, &mut updated);
            scalar_row(&[1, factor], &srcs, done, &mut updated[done..]);
            row.copy_from_slice(&updated);
        }
    }
    Some(rows.chunks_exact(width).flat_map(|row| &row[size..]).copied().collect())
}

/// Inverts a `k x k` matrix over `GF(2^8)` using Gauss–Jordan elimination.
pub fn invert_matrix(mat: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let k = mat.len();
    let inverse = (CODE.invert)(k, &mat.concat()).expect("singular matrix in GF(2^8)");
    inverse.chunks_exact(k.max(1)).map(<[u8]>::to_vec).collect()
}

/// Writes the chunks `rows` of the `(srcs.len(), n)` code, parity ones
/// (`srcs.len() <= row < n`), of the data segments `srcs` into `dsts`. Every
/// segment is the same length.
pub fn rs_parity_rows(srcs: &[&[u8]], n: usize, rows: &[usize], dsts: &mut [&mut [u8]]) {
    (CODE.parity_rows)(srcs, n, rows, dsts)
}

fn parity_rows<K: Kernel>(srcs: &[&[u8]], n: usize, rows: &[usize], dsts: &mut [&mut [u8]]) {
    let k = srcs.len();
    assert!(k >= 1 && rows.len() == dsts.len() && rows.iter().all(|r| (k..n).contains(r)));
    if n > MAX_NARROW_CHUNKS {
        assert!(gf16::takes(k, n, srcs[0].len()));
        return gf16::parity::<K>(srcs, rows, dsts);
    }
    // The transform costs the same whatever the rows asked for, the matrix a
    // pass over the data for each: the transform from a number of rows that
    // grows with its depth.
    let enough = rows.len() >= K::FFT_FROM_HALF_ROWS * k.max(1).ilog2() as usize / 2;
    let fft = n == 2 * k && k.is_power_of_two() && enough;
    if fft && !srcs[0].is_empty() {
        return fft::parity::<K>(srcs, rows, dsts);
    }
    let parity = parity_of::<K>(k, n);
    if rows.iter().copied().eq(k..n) {
        return combine(&parity, srcs, dsts);
    }
    let picked = rows.iter().flat_map(|&r| parity.row(r - k)).copied().collect();
    combine(&Matrix::<K>::new(k, picked), srcs, dsts);
}

/// Computes `k` parity chunks of length `segment_size` from `k` equal-sized
/// (padded) data segments (`rs_parity(pad_each(segs, size), K)` in
/// `seacast-lite.md` §1 `[c6]`).
pub fn rs_parity(padded_data_segs: &[Vec<u8>], parity_count: usize) -> Vec<Vec<u8>> {
    let k = padded_data_segs.len();
    assert!(k >= 1 && k + parity_count <= MAX_WIDE_CHUNKS);
    let srcs: Vec<&[u8]> = padded_data_segs.iter().map(Vec::as_slice).collect();
    let rows: Vec<usize> = (k..k + parity_count).collect();
    let mut parity = vec![vec![0u8; srcs[0].len()]; parity_count];
    let mut dsts: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
    rs_parity_rows(&srcs, k + parity_count, &rows, &mut dsts);
    parity
}

/// The combination that gives the missing data segments of the `(k, n)` code
/// from `k` of its chunks, `indices`, distinct and below `n`: the missing
/// segments, lowest first, and a matrix with a row for each and a column per
/// chunk, in the order `indices` names them. No matrix if nothing is missing.
///
/// The data are the values at the points `0..k` of a polynomial below degree
/// `k`, a chunk its value at the chunk's index. So a missing segment `c` is the
/// sum over the chunks `s` held of chunk `s` times the Lagrange basis
/// polynomial of `s` at `c`: the product of `c - t` over the others held, over
/// that of `s - t`. No difference is zero, so the products are sums of
/// logarithms.
fn solve_missing<K: Kernel>(
    k: usize,
    n: usize,
    indices: &[u32],
) -> Option<(Vec<usize>, Option<Matrix<K>>)> {
    if k == 0 || n > 256 || k > n || indices.len() != k {
        return None;
    }
    // Where each chunk of the code is among `indices`.
    let mut position = [usize::MAX; 256];
    for (at, &index) in indices.iter().enumerate() {
        let index = index as usize;
        if index >= n || position[index] != usize::MAX {
            return None;
        }
        position[index] = at;
    }
    let missing: Vec<usize> = (0..k).filter(|&c| position[c] == usize::MAX).collect();
    if missing.is_empty() {
        return Some((missing, None));
    }

    // The logarithm of the product of `x - t` over the chunks held but `x`.
    let log = |x: u32| GF256.log[x as usize] as u32;
    let others =
        |x: u32| indices.iter().filter(|&&t| t != x).map(|&t| log(x ^ t)).sum::<u32>() % 255;
    let denominators: Vec<u32> = indices.iter().map(|&s| others(s)).collect();
    let mut solve = vec![0u8; missing.len() * k];
    for (row, &c) in solve.chunks_exact_mut(k).zip(&missing) {
        let c = c as u32;
        let numerator = others(c);
        for ((out, &s), denominator) in row.iter_mut().zip(indices).zip(&denominators) {
            // All but the factor `c - s`, over the denominator.
            let exponent = numerator + (255 - log(c ^ s)) + (255 - denominator);
            *out = GF256.exp[exponent as usize % 255];
        }
    }
    Some((missing, Some(Matrix::new(k, solve))))
}

/// Recovers the data segments of the `(k, n)` code from `k` chunks: chunk
/// `indices[i]` is `chunks[i]`, every one `segment_size` bytes, the indices
/// distinct and below `n`. `data` is the `k` segments end to end. A data chunk
/// among the `k` is copied to its place; only the others are computed.
///
/// `None` if the chunks are not `k` distinct chunks of the code.
pub fn rs_reconstruct_into(
    k: usize,
    n: usize,
    indices: &[u32],
    chunks: &[&[u8]],
    data: &mut [u8],
) -> Option<()> {
    (CODE.reconstruct_into)(k, n, indices, chunks, data)
}

fn reconstruct_into<K: Kernel>(
    k: usize,
    n: usize,
    indices: &[u32],
    chunks: &[&[u8]],
    data: &mut [u8],
) -> Option<()> {
    if k == 0 || chunks.len() != k || !data.len().is_multiple_of(k) {
        return None;
    }
    let size = data.len() / k;
    if chunks.iter().any(|chunk| chunk.len() != size) {
        return None;
    }
    if n > MAX_NARROW_CHUNKS {
        return reconstruct_wide::<K>(k, n, indices, chunks, data);
    }
    let (missing, solve) = solve_missing::<K>(k, n, indices)?;
    let mut dsts = Vec::with_capacity(missing.len());
    for (c, segment) in data.chunks_exact_mut(size.max(1)).enumerate() {
        match indices.iter().position(|&index| index as usize == c) {
            Some(at) => segment.copy_from_slice(chunks[at]),
            None => dsts.push(segment),
        }
    }
    if let (Some(solve), true) = (solve, size > 0) {
        combine(&solve, chunks, &mut dsts);
    }
    Some(())
}

/// [`rs_reconstruct_into`] over `GF(2^16)`.
fn reconstruct_wide<K: Kernel>(
    k: usize,
    n: usize,
    indices: &[u32],
    chunks: &[&[u8]],
    data: &mut [u8],
) -> Option<()> {
    let size = data.len() / k;
    if !gf16::takes(k, n, size) || indices.iter().any(|&index| index as usize >= n) {
        return None;
    }
    let known: Vec<(usize, &[u8])> =
        indices.iter().map(|&index| index as usize).zip(chunks.iter().copied()).collect();
    let mut place = vec![usize::MAX; k];
    for (at, &(index, _)) in known.iter().enumerate() {
        if let Some(place) = place.get_mut(index) {
            *place = at;
        }
    }
    let wanted: Vec<usize> = (0..k).filter(|&c| place[c] == usize::MAX).collect();
    let mut dsts = Vec::with_capacity(wanted.len());
    for (c, segment) in data.chunks_exact_mut(size.max(1)).enumerate() {
        match place[c] {
            usize::MAX => dsts.push(segment),
            at => segment.copy_from_slice(chunks[at]),
        }
    }
    gf16::restore::<K>(k, size, &known, &wanted, &mut dsts)
}

/// Fills in every chunk of the `(k, n)` code that is missing, where the chunks
/// are kept: `data` is the `k` data segments end to end and `parity` the `n -
/// k` parity ones, every one the same length, and `have(i)` says chunk `i` is
/// there. Nothing present is moved or rewritten: a missing data segment is
/// computed from the data present and as many parity chunks as data
/// segments are missing, and a missing parity chunk from the data once it is
/// whole.
///
/// `None`, with nothing written, if fewer than `k` chunks are present.
pub fn rs_complete_in_place(
    k: usize,
    n: usize,
    data: &mut [u8],
    parity: &mut [u8],
    have: impl Fn(usize) -> bool,
) -> Option<()> {
    rs_complete_data_in_place(k, n, data, parity, &have)?;
    let size = data.len() / k;
    if size == 0 {
        return Some(());
    }
    let rows: Vec<usize> = (k..n).filter(|&r| !have(r)).collect();
    if !rows.is_empty() {
        let srcs: Vec<&[u8]> = data.chunks_exact(size).collect();
        let mut dsts: Vec<&mut [u8]> = (parity.chunks_exact_mut(size).enumerate())
            .filter(|(r, _)| !have(k + r))
            .map(|(_, segment)| segment)
            .collect();
        rs_parity_rows(&srcs, n, &rows, &mut dsts);
    }
    Some(())
}

/// The data half of [`rs_complete_in_place`]: the missing data segments are
/// filled in and `parity` is left as it is.
pub fn rs_complete_data_in_place(
    k: usize,
    n: usize,
    data: &mut [u8],
    parity: &[u8],
    have: impl Fn(usize) -> bool,
) -> Option<()> {
    (CODE.complete_data_in_place)(k, n, data, parity, &have)
}

fn complete_data_in_place<K: Kernel>(
    k: usize,
    n: usize,
    data: &mut [u8],
    parity: &[u8],
    have: &dyn Fn(usize) -> bool,
) -> Option<()> {
    if k == 0 || k > n || n > MAX_WIDE_CHUNKS || !data.len().is_multiple_of(k) {
        return None;
    }
    let size = data.len() / k;
    if parity.len() != (n - k) * size {
        return None;
    }
    if n > MAX_NARROW_CHUNKS && !gf16::takes(k, n, size) {
        return None;
    }
    let missing_data = (0..k).filter(|&c| !have(c)).count();
    let parity_used: Vec<usize> = (k..n).filter(|&r| have(r)).take(missing_data).collect();
    if parity_used.len() < missing_data {
        return None;
    }
    if size == 0 || missing_data == 0 {
        return Some(());
    }
    let indices: Vec<u32> =
        (0..k).filter(|&c| have(c)).chain(parity_used).map(|i| i as u32).collect();
    if n > MAX_NARROW_CHUNKS {
        let (mut known, mut dsts) = (Vec::with_capacity(k), Vec::with_capacity(missing_data));
        for (c, segment) in data.chunks_exact_mut(size).enumerate() {
            if have(c) {
                known.push((c, &*segment));
            } else {
                dsts.push(segment);
            }
        }
        let wanted: Vec<usize> = (0..k).filter(|&c| !have(c)).collect();
        known.extend(indices[known.len()..].iter().map(|&r| {
            let r = r as usize;
            (r, &parity[(r - k) * size..][..size])
        }));
        return gf16::restore::<K>(k, size, &known, &wanted, &mut dsts);
    }
    let (_, solve) = solve_missing::<K>(k, n, &indices)?;
    let (mut srcs, mut dsts) = (Vec::with_capacity(k), Vec::with_capacity(missing_data));
    for (c, segment) in data.chunks_exact_mut(size).enumerate() {
        if have(c) {
            srcs.push(&*segment);
        } else {
            dsts.push(segment);
        }
    }
    srcs.extend(indices[srcs.len()..].iter().map(|&r| &parity[(r as usize - k) * size..][..size]));
    combine(&solve?, &srcs, &mut dsts);
    Some(())
}

/// Reconstructs the `k` padded data segments of length `segment_size` from any
/// `k` distinct `(index, padded_chunk_bytes)` pairs in `0..n`.
pub fn rs_reconstruct_data(
    k: usize,
    n: usize,
    segment_size: usize,
    available: &[(u32, Vec<u8>)],
) -> Option<Vec<Vec<u8>>> {
    if available.len() < k || k == 0 || n > MAX_WIDE_CHUNKS {
        return None;
    }
    let indices: Vec<u32> = available[..k].iter().map(|(index, _)| *index).collect();
    let chunks: Vec<&[u8]> = available[..k].iter().map(|(_, bytes)| bytes.as_slice()).collect();
    if chunks.iter().any(|chunk| chunk.len() != segment_size) {
        return None;
    }
    let mut data = vec![0u8; k * segment_size];
    rs_reconstruct_into(k, n, &indices, &chunks, &mut data)?;
    if segment_size == 0 {
        return Some(vec![Vec::new(); k]);
    }
    Some(data.chunks_exact(segment_size).map(<[u8]>::to_vec).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator as the protocol defines it: the Vandermonde matrix of the
    /// points, times the inverse of its top square.
    fn vandermonde_generator(k: usize, n: usize) -> Vec<Vec<u8>> {
        let v: Vec<Vec<u8>> =
            (0..n).map(|r| (0..k).map(|c| GF256.pow(r as u8, c)).collect()).collect();
        let top_inv = invert_matrix(&v[..k]);
        v.iter()
            .map(|row| {
                (0..k)
                    .map(|c| (0..k).fold(0, |acc, j| acc ^ GF256.mul(row[j], top_inv[j][c])))
                    .collect()
            })
            .collect()
    }

    fn bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    #[test]
    fn test_generator_is_the_vandermonde_one() {
        for (k, n) in [(1, 2), (2, 4), (3, 6), (5, 9), (16, 32), (37, 74), (128, 256), (100, 256)] {
            assert_eq!(build_systematic_matrix(k, n), vandermonde_generator(k, n), "({k}, {n})");
        }
    }

    /// The kernel in use against the table, at lengths around every vector
    /// width and strip.
    #[test]
    fn test_parity_matches_the_table() {
        let k = 7;
        let generator = build_systematic_matrix(k, 2 * k);
        for size in [0, 1, 15, 16, 17, 31, 33, 63, 64, 65, 255, 257, 1023, 1024, 1025, 2500] {
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (size * 31 + i) as u64)).collect();
            let parity = rs_parity(&data, k);
            for (p, row) in parity.iter().enumerate() {
                for (at, &byte) in row.iter().enumerate() {
                    let expected =
                        (0..k).fold(0, |acc, c| acc ^ GF256.mul(generator[k + p][c], data[c][at]));
                    assert_eq!(byte, expected, "size {size} parity {p} byte {at}");
                }
            }
        }
    }

    /// The transform against the matrix: every `k` it takes, lengths around
    /// every vector width and strip, all the parity rows and some of them.
    fn fft_parity_is_the_matrix_one<K: Kernel>() {
        for k in [1usize, 2, 4, 8, 16, 32, 64, 128] {
            let matrix = parity_matrix::<K>(k, 2 * k);
            for size in [1, 15, 16, 17, 63, 64, 65, 255, 1023, 1024, 1025, 2500] {
                let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k * 13 + i) as u64)).collect();
                let srcs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
                let mut expected = vec![vec![0u8; size]; k];
                combine(
                    &matrix,
                    &srcs,
                    &mut expected.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>(),
                );
                for step in [1, 3] {
                    // Highest first, so a row's place in `rows` is not its place in the code.
                    let rows: Vec<usize> = (k..2 * k).rev().step_by(step).collect();
                    let mut parity = vec![vec![0x5au8; size]; rows.len()];
                    let mut dsts: Vec<&mut [u8]> =
                        parity.iter_mut().map(Vec::as_mut_slice).collect();
                    fft::parity::<K>(&srcs, &rows, &mut dsts);
                    for (r, row) in rows.iter().zip(&parity) {
                        assert!(row == &expected[r - k], "k {k} size {size} row {r}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_fft_parity_is_the_matrix_one() {
        each_kernel!(fft_parity_is_the_matrix_one);
    }

    /// The parity, by the matrix and by the transform, and the data back from
    /// the parity alone and from a mix, over both fields: the bytes the table
    /// gives, at lengths around every vector width and strip.
    fn kernel_gives_the_tables_bytes<K: Kernel>() {
        let (code, table) = (Code::of::<K>(), Code::of::<portable::Portable>());
        for (k, size) in [(7, 0), (7, 65), (7, 2500), (16, 1025), (128, 1088), (200, 1088)] {
            let n = 2 * k;
            let data = bytes(k * size, (k * 17 + size) as u64);
            let srcs: Vec<&[u8]> = data.chunks_exact(size.max(1)).take(k).collect();
            let srcs = if size == 0 { vec![&[][..]; k] } else { srcs };
            let rows: Vec<usize> = (k..n).collect();
            let parity_by = |code: &Code, rows: &[usize]| {
                let mut parity = vec![0x5au8; rows.len() * size];
                let mut dsts: Vec<&mut [u8]> = match size {
                    0 => rows.iter().map(|_| &mut [][..]).collect(),
                    _ => parity.chunks_exact_mut(size).collect(),
                };
                (code.parity_rows)(&srcs, n, rows, &mut dsts);
                parity
            };
            let parity = parity_by(&table, &rows);
            assert!(parity_by(&code, &rows) == parity, "parity ({k}, {n}) size {size}");
            assert!(
                parity_by(&code, &rows[1..3]) == parity[size..3 * size],
                "two rows ({k}, {n}) size {size}"
            );

            let indices: Vec<u32> = (k as u32..n as u32).collect();
            let chunks: Vec<&[u8]> = match size {
                0 => vec![&[][..]; k],
                _ => parity.chunks_exact(size).collect(),
            };
            let mut back = vec![0x5au8; k * size];
            assert_eq!((code.reconstruct_into)(k, n, &indices, &chunks, &mut back), Some(()));
            assert!(back == data, "reconstruct ({k}, {n}) size {size}");

            let have = |i: usize| !i.is_multiple_of(3);
            let mut holed = data.clone();
            for c in (0..k).filter(|&c| !have(c)) {
                holed[c * size..][..size].fill(0x5a);
            }
            let done = (code.complete_data_in_place)(k, n, &mut holed, &parity, &have);
            assert_eq!(done, Some(()));
            assert!(holed == data, "complete ({k}, {n}) size {size}");
        }
        let matrix = parity_bytes(13, 13 + 13);
        assert_eq!((code.invert)(13, &matrix), (table.invert)(13, &matrix));
    }

    #[test]
    fn test_every_kernel_gives_the_tables_bytes() {
        each_kernel!(kernel_gives_the_tables_bytes);
    }

    /// Any `k` chunks give the data back: every mix of data and parity chunks,
    /// in any order.
    #[test]
    fn test_reconstruct_from_any_chunks() {
        for (k, n, size) in [(1, 2, 70), (4, 8, 100), (13, 26, 67), (128, 256, 96), (10, 30, 65)] {
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k * 7 + i) as u64)).collect();
            let mut chunks = data.clone();
            chunks.extend(rs_parity(&data, n - k));
            for trial in 0..20u64 {
                // A pseudo-random order of all the chunks; its first `k` are the ones received.
                let mut order: Vec<u32> = (0..n as u32).collect();
                let keys = bytes(n, 1000 + trial);
                order.sort_by_key(|&i| (keys[i as usize], i));
                let available: Vec<(u32, Vec<u8>)> =
                    order[..k].iter().map(|&i| (i, chunks[i as usize].clone())).collect();
                assert_eq!(
                    rs_reconstruct_data(k, n, size, &available).as_ref(),
                    Some(&data),
                    "({k}, {n}) trial {trial}"
                );
            }
            // The data alone, and the parity alone when there is enough of it.
            let all_data: Vec<(u32, Vec<u8>)> =
                (0..k).map(|i| (i as u32, chunks[i].clone())).collect();
            assert_eq!(rs_reconstruct_data(k, n, size, &all_data).as_ref(), Some(&data));
            let all_parity: Vec<(u32, Vec<u8>)> =
                (k..2 * k).map(|i| (i as u32, chunks[i].clone())).collect();
            assert_eq!(rs_reconstruct_data(k, n, size, &all_parity).as_ref(), Some(&data));
        }
    }

    /// Whatever is missing of a group kept in place is filled in, and nothing
    /// present is touched.
    #[test]
    fn test_complete_in_place() {
        for (k, n, size) in [(1, 2, 70), (4, 8, 100), (13, 26, 67), (128, 256, 96), (10, 30, 65)] {
            let data: Vec<Vec<u8>> = (0..k).map(|i| bytes(size, (k * 11 + i) as u64)).collect();
            let whole_data = data.concat();
            let whole_parity = rs_parity(&data, n - k).concat();
            for trial in 0..20u64 {
                // A pseudo-random set of at least `k` chunks.
                let keys = bytes(n, 2000 + trial);
                let mut order: Vec<usize> = (0..n).collect();
                order.sort_by_key(|&i| (keys[i], i));
                let present = &order[..k + (trial as usize % (n - k + 1))];
                let have = |i: usize| present.contains(&i);
                // What is missing starts as junk; what is present must come out as it went in.
                let (mut data, mut parity) = (whole_data.clone(), whole_parity.clone());
                for i in (0..n).filter(|&i| !have(i)) {
                    let slot = if i < k {
                        &mut data[i * size..][..size]
                    } else {
                        &mut parity[(i - k) * size..][..size]
                    };
                    slot.fill(0x5a);
                }
                assert_eq!(rs_complete_in_place(k, n, &mut data, &mut parity, have), Some(()));
                assert!(data == whole_data && parity == whole_parity, "({k}, {n}) trial {trial}");
            }
            let (mut data, mut parity) = (whole_data.clone(), whole_parity.clone());
            assert_eq!(
                rs_complete_in_place(k, n, &mut data, &mut parity, |i| i >= 1 && i < k),
                None
            );
            assert!(data == whole_data && parity == whole_parity);
        }
    }

    #[test]
    fn test_reconstruct_refuses_bad_chunks() {
        let data: Vec<Vec<u8>> = (0..4).map(|i| bytes(40, i)).collect();
        let parity = rs_parity(&data, 4);
        let chunk =
            |i: usize| (i as u32, if i < 4 { data[i].clone() } else { parity[i - 4].clone() });
        // A chunk given twice, an index outside the code, a chunk of another length.
        assert_eq!(rs_reconstruct_data(4, 8, 40, &[chunk(0), chunk(5), chunk(5), chunk(7)]), None);
        assert_eq!(
            rs_reconstruct_data(4, 8, 40, &[chunk(0), chunk(1), chunk(2), (8, vec![0; 40])]),
            None
        );
        assert_eq!(
            rs_reconstruct_data(4, 8, 40, &[chunk(0), chunk(1), chunk(2), (5, vec![0; 39])]),
            None
        );
        assert_eq!(rs_reconstruct_data(4, 8, 40, &[chunk(0), chunk(1), chunk(2)]), None);
    }

    #[test]
    fn test_reed_solomon_roundtrip() {
        let k = 8;
        let n = 16;
        let seg_size = 64;
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..seg_size).map(|j| ((i * 31 + j * 17 + 5) & 0xff) as u8).collect())
            .collect();
        let parity = rs_parity(&data, k);
        assert_eq!(parity.len(), k);

        let mut all_chunks: Vec<(u32, Vec<u8>)> = Vec::new();
        for (i, seg) in data.iter().enumerate() {
            all_chunks.push((i as u32, seg.clone()));
        }
        for (i, seg) in parity.iter().enumerate() {
            all_chunks.push(((k + i) as u32, seg.clone()));
        }

        // Take odd indices only (half data, half parity)
        let subset: Vec<(u32, Vec<u8>)> =
            all_chunks.into_iter().filter(|(idx, _)| idx % 2 == 1).collect();
        assert_eq!(subset.len(), k);

        let recovered = rs_reconstruct_data(k, n, seg_size, &subset).expect("decode succeeds");
        assert_eq!(recovered, data);
    }
}
