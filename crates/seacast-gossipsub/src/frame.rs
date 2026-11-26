//! A gossipsub `RPC` to and from the node: [`Inbound`] for one received,
//! [`write_entry`] for one written.
//!
//! A received `RPC`. An `RPC` can hold several
//! chunks and any number of control entries, SEACAST's and others, where the
//! node's [`Rpc`] holds one chunk and a fixed count of each message. The host
//! walks its parsed `RPC`, keeps what is not SEACAST's and every GRAFT and
//! PRUNE (the mesh is the host's: `SeacastNode::relation_added`), and puts the
//! rest into an [`Inbound`], which hands a part to `sink` whenever one is full.
//! `sink` is `SeacastNode::on_frame_part(peer, rpc, offered, ..)`, and returns
//! its result.

use seacast_core::{ChunkMsg, Have, Join, QueueEntry, Rpc, TypeId, Want};

use crate::control::{MAX_HAVE_STRING, holding_string, offer_string, want_strings};

/// One peer's frame, in the making.
///
/// The node handles a part's holdings after its asks, and the specification a
/// frame's (`seacast.md` §4 `on_frame`): the host puts the IDONTWANT entries
/// last. [`finish`](Self::finish) hands over what is left.
pub struct Inbound<B> {
    part: Rpc<B>,
    offered: bool,
}

impl<B> Default for Inbound<B> {
    fn default() -> Self {
        Self { part: Rpc::default(), offered: false }
    }
}

impl<B> Inbound<B> {
    pub fn new() -> Self {
        Self::default()
    }

    fn flush(&mut self, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        if !self.part.is_empty() {
            self.offered = sink(std::mem::take(&mut self.part), self.offered);
        }
    }

    /// A subscription to a topic of a type, as the type's JOIN
    /// (`seacast-bindings.md` §0).
    pub fn join(&mut self, join: Join, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        if self.part.joins.is_full() {
            self.flush(sink);
        }
        let _ = self.part.joins.push(join);
    }

    /// A message on a SEACAST topic (`PayloadCodec::read_message`).
    pub fn chunk(&mut self, chunk: ChunkMsg<B>, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        if self.part.chunk.is_some() {
            self.flush(sink);
        }
        self.part.chunk = Some(chunk);
    }

    /// An IHAVE entry that is an offer ([`read_offer`](crate::read_offer)).
    pub fn offer(&mut self, offer: Have, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        self.have(offer, sink);
    }

    /// An IDONTWANT entry that is a holding
    /// ([`read_holding`](crate::read_holding)).
    pub fn holding(&mut self, holding: Have, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        self.have(holding, sink);
    }

    fn have(&mut self, have: Have, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        if self.part.haves.is_full() {
            self.flush(sink);
        }
        let _ = self.part.haves.push(have);
    }

    /// An IWANT entry that is a WANT ([`read_want`](crate::read_want)). The
    /// strings name one index each: those of one group and one set of flags
    /// are one WANT of the node's.
    pub fn want(&mut self, want: Want, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        let same = |w: &&mut Want| {
            (w.group, w.standing, w.probe, w.hops) ==
                (want.group, want.standing, want.probe, want.hops)
        };
        if let Some(w) = self.part.wants.as_mut_slice().iter_mut().find(same) {
            for index in want.bits.iter() {
                w.bits.set(index);
            }
            return;
        }
        if self.part.wants.is_full() {
            self.flush(sink);
        }
        let _ = self.part.wants.push(want);
    }

    /// The end of the frame.
    pub fn finish(mut self, sink: &mut impl FnMut(Rpc<B>, bool) -> bool) {
        self.flush(sink);
    }
}

/// Where a `QueueEntry` is written: the host's `RPC` to one peer.
pub trait RpcOut<B> {
    /// A chunk, as a message on its topic: its data is the frame compressed
    /// with snappy, its id [`message_id_of`] the chunk's.
    fn message(&mut self, chunk: &ChunkMsg<B>);
    /// An entry of an IHAVE on the topic of `object_type`.
    fn ihave(&mut self, object_type: TypeId, entry: &[u8]);
    /// An entry of an IWANT.
    fn iwant(&mut self, entry: &[u8]);
    /// An entry of an IDONTWANT.
    fn idontwant(&mut self, entry: &[u8]);
}

/// Writes what `SeacastNode::next_to_send` gave. The entry's JOINs write
/// nothing: the host's subscription has said them (`seacast-bindings.md` §6).
/// Its GRAFTs and PRUNEs are none where the host keeps the relations.
pub fn write_entry<B>(entry: &QueueEntry<B>, out: &mut impl RpcOut<B>) {
    if let Some(chunk) = &entry.chunk {
        out.message(chunk);
    }
    let mut string = [0u8; MAX_HAVE_STRING];
    for have in &entry.haves {
        if have.offer {
            let len = offer_string(have, &mut string);
            out.ihave(have.group.type_id, &string[..len]);
        } else {
            let len = holding_string(have, &mut string);
            out.idontwant(&string[..len]);
        }
    }
    for want in &entry.wants {
        want_strings(want, |entry| out.iwant(entry));
    }
}

#[cfg(test)]
mod tests {
    use seacast_core::{Bitmap, MAX_ENTRY_CONTROL};

    use super::*;
    use crate::payload::payload_group;

    #[test]
    fn test_parts() {
        let mut parts: Vec<Rpc<Vec<u8>>> = Vec::new();
        let mut offered_in = Vec::new();
        let mut sink = |rpc: Rpc<Vec<u8>>, offered: bool| {
            offered_in.push(offered);
            let offers = rpc.haves.iter().any(|h| h.offer);
            parts.push(rpc);
            offered || offers
        };
        let group = |tag: u8| payload_group([tag; 32]);
        let mut frame = Inbound::new();
        // The indices of one group and flags are one WANT; other flags another.
        for index in 0..40 {
            frame.want(Want::direct(group(1), Bitmap::singleton(index)), &mut sink);
        }
        frame.want(Want::standing(group(1), Bitmap::singleton(3)), &mut sink);
        frame.offer(Have::offer(group(1), Bitmap::singleton(0)), &mut sink);
        // More groups than a part holds.
        for tag in 2..2 + MAX_ENTRY_CONTROL as u8 {
            frame.want(Want::direct(group(tag), Bitmap::singleton(0)), &mut sink);
        }
        frame.holding(Have::holding(group(1), Bitmap::singleton(0), false, false), &mut sink);
        frame.finish(&mut sink);

        assert_eq!(parts.len(), 2);
        assert_eq!(offered_in, [false, true]);
        assert_eq!(parts[0].wants.len(), MAX_ENTRY_CONTROL);
        assert_eq!(parts[0].wants.as_slice()[0].bits, Bitmap::all_bits(40));
        assert!(parts[0].wants.as_slice()[1].standing);
        assert_eq!(parts[0].haves.len(), 1);
        assert_eq!(parts[1].wants.len(), 2);
        assert!(!parts[1].haves.as_slice()[0].offer);
    }
}
