use std::{
    fmt,
    hash::Hash,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use fxhash::{FxHashMap, FxHashSet};

use crate::types::{GenerationPeerId, PeerId};

/// Maximum connected peers supported by inline peer sets (`MAX_PEERS`).
pub const MAX_INLINE_PEERS: usize = 64;

/// Maximum offers tracked per `(group, index)` ask (`MAX_OFFERS_PER_ASK` in
/// `seacast-lite.md` §8.1).
pub const MAX_INLINE_OFFERS: usize = 16;

/// Maximum colours per family in inline lists.
pub const MAX_INLINE_COLOURS: usize = 64;

/// Maximum control items (`Join`, `Graft`, `Prune`, `Have`, `Want`) bundled in
/// a single [`QueueEntry`].
pub const MAX_ENTRY_CONTROL: usize = 16;

/// Maximum projected `(GroupId, u32)` pairs per chunk (`R4`: column + row = 2).
/// Object types a node may join.
pub const MAX_JOINED_TYPES: usize = 256;

pub const MAX_PROJECTED: usize = 4;

/// Maximum chunks per group in inline lists (`MAX_CHUNKS`).
pub const MAX_CHUNKS: usize = 256;

/// A stack-allocated, fixed-capacity vector for `Copy` elements with **zero
/// heap allocation**.
#[derive(Copy, Clone)]
pub struct InlineVec<T: Copy, const CAP: usize> {
    len: usize,
    data: [MaybeUninit<T>; CAP],
}

impl<T: Copy, const CAP: usize> Default for InlineVec<T, CAP> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const CAP: usize> InlineVec<T, CAP> {
    /// Creates an empty `InlineVec`.
    #[inline]
    pub const fn new() -> Self {
        Self { len: 0, data: [MaybeUninit::uninit(); CAP] }
    }

    /// Creates an `InlineVec` containing a single item.
    #[inline]
    pub fn singleton(item: T) -> Self {
        let mut v = Self::new();
        let _ = v.push(item);
        v
    }

    /// Creates an `InlineVec` from a slice (truncating to `CAP` if longer).
    #[inline]
    pub fn from_slice(slice: &[T]) -> Self {
        let mut v = Self::new();
        let n = slice.len().min(CAP);
        for (i, &item) in slice[..n].iter().enumerate() {
            v.data[i] = MaybeUninit::new(item);
        }
        v.len = n;
        v
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub const fn capacity(&self) -> usize {
        CAP
    }

    #[inline]
    pub const fn is_full(&self) -> bool {
        self.len >= CAP
    }

    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `self.data[..self.len]` is guaranteed initialized.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr() as *const T, self.len) }
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: `self.data[..self.len]` is guaranteed initialized.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut T, self.len) }
    }

    /// Appends `item` if capacity permits, returning `true` if inserted.
    #[inline]
    pub fn push(&mut self, item: T) -> bool {
        if self.len >= CAP {
            return false;
        }
        self.data[self.len] = MaybeUninit::new(item);
        self.len += 1;
        true
    }

    /// Appends all elements from `other` that fit within `CAP`.
    #[inline]
    pub fn extend_from_slice(&mut self, other: &[T]) {
        for &item in other {
            if !self.push(item) {
                break;
            }
        }
    }

    /// Removes and returns the element at `index`, shifting subsequent elements
    /// left.
    #[inline]
    pub fn remove(&mut self, index: usize) -> T {
        assert!(index < self.len, "InlineVec::remove out of bounds");
        let item = unsafe { self.data[index].assume_init() };
        for i in index..(self.len - 1) {
            self.data[i] = self.data[i + 1];
        }
        self.len -= 1;
        item
    }

    /// Truncates the vector to at most `new_len` elements.
    #[inline]
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            self.len = new_len;
        }
    }

    /// Retains only the elements specified by the predicate.
    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut f: F) {
        let mut write = 0;
        for read in 0..self.len {
            let val = unsafe { self.data[read].assume_init_ref() };
            if f(val) {
                if write != read {
                    self.data[write] = self.data[read];
                }
                write += 1;
            }
        }
        self.len = write;
    }
}

impl<T: Copy + PartialEq, const CAP: usize> InlineVec<T, CAP> {
    /// Returns `true` if `item` is present.
    #[inline]
    pub fn contains(&self, item: &T) -> bool {
        self.as_slice().contains(item)
    }

    /// Inserts `item` if not already present and capacity permits. Returns
    /// `true` if newly added.
    #[inline]
    pub fn insert_unique(&mut self, item: T) -> bool {
        if self.contains(&item) {
            return false;
        }
        self.push(item)
    }

    /// Removes the first occurrence of `item`, returning `true` if removed.
    #[inline]
    pub fn remove_item(&mut self, item: &T) -> bool {
        if let Some(pos) = self.as_slice().iter().position(|x| x == item) {
            self.remove(pos);
            true
        } else {
            false
        }
    }
}

impl<T: Copy, const CAP: usize> Deref for InlineVec<T, CAP> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T: Copy, const CAP: usize> AsRef<[T]> for InlineVec<T, CAP> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy, const CAP: usize> DerefMut for InlineVec<T, CAP> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T: Copy + PartialEq, const CAP: usize> PartialEq for InlineVec<T, CAP> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + Eq, const CAP: usize> Eq for InlineVec<T, CAP> {}

impl<T: Copy + fmt::Debug, const CAP: usize> fmt::Debug for InlineVec<T, CAP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<'a, T: Copy, const CAP: usize> IntoIterator for &'a InlineVec<T, CAP> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Copy, const CAP: usize> IntoIterator for InlineVec<T, CAP> {
    type Item = T;
    type IntoIter = InlineVecIntoIter<T, CAP>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        InlineVecIntoIter { vec: self, index: 0 }
    }
}

pub struct InlineVecIntoIter<T: Copy, const CAP: usize> {
    vec: InlineVec<T, CAP>,
    index: usize,
}

impl<T: Copy, const CAP: usize> Iterator for InlineVecIntoIter<T, CAP> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.vec.len {
            let item = unsafe { self.vec.data[self.index].assume_init() };
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

/// A preallocated fixed-capacity vector allocated once at initialization.
/// Never reallocates on the heap after construction.
#[derive(Clone)]
pub struct PreallocVec<T> {
    cap: usize,
    inner: Vec<T>,
}

impl<T> PreallocVec<T> {
    /// Preallocates a vector with fixed capacity `cap`.
    pub fn with_capacity(cap: usize) -> Self {
        Self { cap, inner: Vec::with_capacity(cap) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.inner.len() >= self.cap
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner
    }

    /// Pushes `item` without reallocating. Returns `false` if at capacity.
    #[inline]
    pub fn push(&mut self, item: T) -> bool {
        if self.inner.len() >= self.cap {
            return false;
        }
        debug_assert!(self.inner.capacity() >= self.cap);
        self.inner.push(item);
        true
    }

    #[inline]
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }

    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.inner.retain(f);
    }

    #[inline]
    pub fn retain_mut<F: FnMut(&mut T) -> bool>(&mut self, f: F) {
        self.inner.retain_mut(f);
    }
}

impl<T: PartialEq> PreallocVec<T> {
    #[inline]
    pub fn contains(&self, item: &T) -> bool {
        self.inner.contains(item)
    }
}

impl<T> Deref for PreallocVec<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for PreallocVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: fmt::Debug> fmt::Debug for PreallocVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// A preallocated fixed-capacity ring buffer (`FIFO` queue) allocated once at
/// initialization. Never reallocates on the heap after construction.
#[derive(Clone)]
pub struct PreallocDeque<T> {
    slots: Box<[Option<T>]>,
    head: usize,
    tail: usize,
    len: usize,
}

impl<T> PreallocDeque<T> {
    /// Preallocates a ring buffer with fixed capacity `cap`.
    pub fn with_capacity(cap: usize) -> Self {
        let mut v = Vec::with_capacity(cap);
        v.resize_with(cap, || None);
        Self { slots: v.into_boxed_slice(), head: 0, tail: 0, len: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len >= self.slots.len()
    }

    #[inline]
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }

    /// Appends `item` to the back if not full. Returns `true` if inserted.
    #[inline]
    pub fn push_back(&mut self, item: T) -> bool {
        let cap = self.slots.len();
        if self.len >= cap || cap == 0 {
            return false;
        }
        self.slots[self.tail] = Some(item);
        self.tail = (self.tail + 1) % cap;
        self.len += 1;
        true
    }

    /// Pops and returns the front element.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let cap = self.slots.len();
        let item = self.slots[self.head].take();
        self.head = (self.head + 1) % cap;
        self.len -= 1;
        item
    }

    /// Returns a reference to the front element.
    #[inline]
    pub fn front(&self) -> Option<&T> {
        if self.len == 0 { None } else { self.slots[self.head].as_ref() }
    }

    /// Returns a mutable reference to the element at logical offset `index`
    /// (`0..len`).
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        let phys = (self.head + index) % self.slots.len();
        self.slots[phys].as_mut()
    }

    /// Returns a reference to the element at logical offset `index` (`0..len`).
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        let phys = (self.head + index) % self.slots.len();
        self.slots[phys].as_ref()
    }

    /// Removes the element at logical offset `index` (`0..len`) and shifts
    /// subsequent elements.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        let cap = self.slots.len();
        let phys = (self.head + index) % cap;
        let removed = self.slots[phys].take();
        for i in index..(self.len - 1) {
            let cur = (self.head + i) % cap;
            let next = (self.head + i + 1) % cap;
            self.slots[cur] = self.slots[next].take();
        }
        self.tail = (self.tail + cap - 1) % cap;
        self.len -= 1;
        removed
    }

    /// Iterates over elements from front to back.
    #[inline]
    pub fn iter(&self) -> PreallocDequeIter<'_, T> {
        PreallocDequeIter { deque: self, index: 0 }
    }
}

impl<T: PartialEq> PreallocDeque<T> {
    #[inline]
    pub fn contains(&self, item: &T) -> bool {
        self.iter().any(|x| x == item)
    }

    #[inline]
    pub fn position<F: FnMut(&T) -> bool>(&self, mut f: F) -> Option<usize> {
        for i in 0..self.len {
            if let Some(item) = self.get(i) {
                if f(item) {
                    return Some(i);
                }
            }
        }
        None
    }
}

pub struct PreallocDequeIter<'a, T> {
    deque: &'a PreallocDeque<T>,
    index: usize,
}

impl<'a, T> Iterator for PreallocDequeIter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.deque.len {
            let item = self.deque.get(self.index);
            self.index += 1;
            item
        } else {
            None
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for PreallocDeque<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A key-value map of fixed capacity over an `FxHashMap` sized once, at
/// initialization: lookups, inserts and removals are O(1) and **never allocate
/// on the heap**. Iteration is in no key order, but the same from run to run:
/// the hash is not seeded.
///
/// A full map refuses a new key: what a peer sends decides how many keys are
/// asked for, so running out is a limit reached (`seacast-lite.md` §8.2), not a
/// broken invariant.
#[derive(Clone)]
pub struct PreallocMap<K, V> {
    cap: usize,
    entries: FxHashMap<K, V>,
    /// Where a refused key's value is written, so that the entry accessors
    /// still return a place.
    spill: Option<V>,
}

impl<K: Eq + Hash, V> PreallocMap<K, V> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap,
            entries: FxHashMap::with_capacity_and_hasher(cap, Default::default()),
            spill: None,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.cap
    }

    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    /// Inserts or updates `(key, value)`. Returns the previous value if the key
    /// existed. A new key is dropped if the map is full.
    #[inline]
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if self.is_full() && !self.entries.contains_key(&key) {
            return None;
        }
        self.entries.insert(key, value)
    }

    /// Returns a mutable reference to `key`'s value, inserting `default` if
    /// absent. If the map is full the key is not kept: the reference is to
    /// a value that the next such call replaces.
    #[inline]
    pub fn get_or_insert_with<F: FnOnce() -> V>(&mut self, key: K, default: F) -> &mut V {
        if self.is_full() && !self.entries.contains_key(&key) {
            return self.spill.insert(default());
        }
        self.entries.entry(key).or_insert_with(default)
    }

    #[inline]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    /// Retains only entries satisfying `f(&K, &mut V)`.
    #[inline]
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, f: F) {
        self.entries.retain(f);
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries.iter_mut()
    }

    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.keys()
    }
}

impl<K: Eq + Hash, V: Default> PreallocMap<K, V> {
    #[inline]
    pub fn entry_or_default(&mut self, key: K) -> &mut V {
        self.get_or_insert_with(key, V::default)
    }
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for PreallocMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.entries.iter()).finish()
    }
}

/// A set of fixed capacity over an `FxHashSet` sized once, at initialization:
/// as [`PreallocMap`].
#[derive(Clone)]
pub struct PreallocSet<T> {
    cap: usize,
    items: FxHashSet<T>,
}

impl<T: Eq + Hash> PreallocSet<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self { cap, items: FxHashSet::with_capacity_and_hasher(cap, Default::default()) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.items.len() >= self.cap
    }

    #[inline]
    pub fn clear(&mut self) {
        self.items.clear();
    }

    #[inline]
    pub fn contains(&self, item: &T) -> bool {
        self.items.contains(item)
    }

    /// Returns `true` if newly inserted: `false` if it was there, or if the set
    /// is full and it was dropped.
    #[inline]
    pub fn insert(&mut self, item: T) -> bool {
        if self.is_full() && !self.items.contains(&item) {
            return false;
        }
        self.items.insert(item)
    }

    /// Removes `item` if present, returning `true` if removed.
    #[inline]
    pub fn remove(&mut self, item: &T) -> bool {
        self.items.remove(item)
    }

    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.items.retain(f);
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

impl<T: fmt::Debug> fmt::Debug for PreallocSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.items.iter()).finish()
    }
}

/// One record a connection, indexed by `PeerId`. Every slot is allocated at
/// creation. A closed slot stays allocated for the next connection with its
/// id. Indexing panics on a peer id not below the capacity.
#[derive(Debug, Clone)]
pub struct PeerSlab<T> {
    slots: Box<[T]>,
    live: Box<[bool]>,
    /// Counts the connections each slot has had.
    generation: Box<[u32]>,
}

impl<T> PeerSlab<T> {
    pub fn with_capacity(max_peers: usize, slot: impl FnMut() -> T) -> Self {
        Self {
            slots: std::iter::repeat_with(slot).take(max_peers).collect(),
            live: vec![false; max_peers].into_boxed_slice(),
            generation: vec![0; max_peers].into_boxed_slice(),
        }
    }

    #[inline]
    pub fn contains(&self, peer: PeerId) -> bool {
        self.live[peer as usize]
    }

    #[inline]
    pub fn get(&self, peer: PeerId) -> Option<&T> {
        let i = peer as usize;
        self.live[i].then(|| &self.slots[i])
    }

    #[inline]
    pub fn get_mut(&mut self, peer: PeerId) -> Option<&mut T> {
        let i = peer as usize;
        self.live[i].then(|| &mut self.slots[i])
    }

    /// Opens `peer`'s slot. Returns `false` if it was open.
    pub fn open(&mut self, peer: PeerId) -> bool {
        let i = peer as usize;
        let opened = !std::mem::replace(&mut self.live[i], true);
        if opened {
            self.generation[i] = self.generation[i].wrapping_add(1);
        }
        opened
    }

    /// `peer` with the generation of its slot.
    #[inline]
    pub fn stamp(&self, peer: PeerId) -> GenerationPeerId {
        GenerationPeerId::new(peer, self.generation[peer as usize])
    }

    /// The peer of `id`, if the connection `id` was stamped for is open.
    #[inline]
    pub fn resolve(&self, id: GenerationPeerId) -> Option<PeerId> {
        let peer = id.peer_id();
        let i = peer as usize;
        (self.live[i] && self.generation[i] == id.generation()).then_some(peer)
    }

    /// Closes `peer`'s slot and returns it, for the caller to reset.
    pub fn close(&mut self, peer: PeerId) -> Option<&mut T> {
        let i = peer as usize;
        std::mem::replace(&mut self.live[i], false).then(|| &mut self.slots[i])
    }

    /// The open slots, in peer id order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().zip(self.live.iter()).filter(|(_, live)| **live).map(|(slot, _)| slot)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().zip(self.live.iter()).filter(|(_, live)| **live).map(|(slot, _)| slot)
    }
}

/// The peers of word `w` of a bitmask row, in peer id order.
pub fn word_bits(w: usize, word: u64) -> WordBits {
    WordBits { w, left: word }
}

/// The peers of a bitmask row, in peer id order.
pub fn peer_bits(row: &[u64]) -> impl Iterator<Item = PeerId> + '_ {
    row.iter().enumerate().flat_map(|(w, &word)| word_bits(w, word))
}

/// Sets of peers by key: a bitmask of `max_peers` bits a key, all in one block
/// allocated at creation. A key holds a row while its set is not empty. With
/// no row free a new key is refused.
#[derive(Debug, Clone)]
pub struct PeerSets<K> {
    rows: PreallocMap<K, u32>,
    words: Box<[u64]>,
    free: Vec<u32>,
    width: usize,
}

impl<K: Eq + Hash + Copy> PeerSets<K> {
    pub fn with_capacity(keys: usize, max_peers: usize) -> Self {
        let width = max_peers.div_ceil(64).max(1);
        Self {
            rows: PreallocMap::with_capacity(keys),
            words: vec![0; keys * width].into_boxed_slice(),
            free: (0..keys as u32).rev().collect(),
            width,
        }
    }

    /// Words a row.
    #[inline]
    pub fn width(&self) -> usize {
        self.width
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.rows.keys()
    }

    /// The keys with a set.
    #[inline]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.rows.contains_key(key)
    }

    /// Whether `insert` would take a peer under `key`: it has a row, or one
    /// is free.
    #[inline]
    pub fn has_room(&self, key: &K) -> bool {
        self.rows.contains_key(key) || !self.free.is_empty()
    }

    /// Drops the set of `key`.
    pub fn remove_key(&mut self, key: &K) {
        if let Some(row) = self.rows.remove(key) {
            let at = row as usize * self.width;
            self.words[at..at + self.width].fill(0);
            self.free.push(row);
        }
    }

    #[inline]
    pub fn row(&self, key: &K) -> Option<&[u64]> {
        let at = *self.rows.get(key)? as usize * self.width;
        Some(&self.words[at..at + self.width])
    }

    #[inline]
    pub fn contains(&self, key: &K, peer: PeerId) -> bool {
        self.row(key).is_some_and(|row| row[peer as usize / 64] & (1 << (peer % 64)) != 0)
    }

    /// Word `w` of the set of `key`.
    #[inline]
    pub fn word(&self, key: &K, w: usize) -> u64 {
        self.rows.get(key).map_or(0, |&row| self.words[row as usize * self.width + w])
    }

    /// The peers of `key`, in peer id order.
    pub fn iter<'a>(&'a self, key: &K) -> impl Iterator<Item = PeerId> + use<'a, K> {
        peer_bits(self.row(key).unwrap_or(&[]))
    }

    pub fn count(&self, key: &K) -> usize {
        self.row(key).map_or(0, |row| row.iter().map(|w| w.count_ones() as usize).sum())
    }

    /// Adds `peer` to the set of `key`. Returns `false` if there is no row for
    /// a new key.
    pub fn insert(&mut self, key: K, peer: PeerId) -> bool {
        let row = match self.rows.get(&key) {
            Some(&row) => row,
            None => {
                let Some(row) = self.free.pop() else {
                    return false;
                };
                self.rows.insert(key, row);
                row
            }
        };
        self.words[row as usize * self.width + peer as usize / 64] |= 1 << (peer % 64);
        true
    }

    /// Takes `peer` out of the set of `key`. Returns whether it was in it.
    pub fn remove(&mut self, key: &K, peer: PeerId) -> bool {
        let Some(&row) = self.rows.get(key) else {
            return false;
        };
        let at = row as usize * self.width;
        let word = &mut self.words[at + peer as usize / 64];
        let was = *word & (1 << (peer % 64)) != 0;
        *word &= !(1 << (peer % 64));
        if was && self.words[at..at + self.width].iter().all(|&w| w == 0) {
            self.rows.remove(key);
            self.free.push(row);
        }
        was
    }

    /// Takes `peer` out of every set.
    pub fn remove_peer(&mut self, peer: PeerId) {
        self.remove_peer_if(peer, |_| true);
    }

    /// Takes `peer` out of the sets of the keys `of` accepts.
    pub fn remove_peer_if(&mut self, peer: PeerId, mut of: impl FnMut(&K) -> bool) {
        let (words, free, width) = (&mut self.words, &mut self.free, self.width);
        self.rows.retain(|key, &mut row| {
            if !of(key) {
                return true;
            }
            let at = row as usize * width;
            words[at + peer as usize / 64] &= !(1 << (peer % 64));
            let kept = words[at..at + width].iter().any(|&w| w != 0);
            if !kept {
                free.push(row);
            }
            kept
        });
    }

    /// Keeps the sets of the keys `keep` accepts.
    pub fn retain_keys(&mut self, mut keep: impl FnMut(&K) -> bool) {
        let (words, free, width) = (&mut self.words, &mut self.free, self.width);
        self.rows.retain(|key, &mut row| {
            let kept = keep(key);
            if !kept {
                let at = row as usize * width;
                words[at..at + width].fill(0);
                free.push(row);
            }
            kept
        });
    }
}

/// The peers of one word of a bitmask row, in peer id order.
#[derive(Debug, Clone)]
pub struct WordBits {
    w: usize,
    left: u64,
}

impl Iterator for WordBits {
    type Item = PeerId;

    #[inline]
    fn next(&mut self) -> Option<PeerId> {
        if self.left == 0 {
            return None;
        }
        let bit = self.left.trailing_zeros() as u64;
        self.left &= self.left - 1;
        Some(self.w as u64 * 64 + bit)
    }
}
