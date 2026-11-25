//! # `seacast-gossipsub`
//!
//! The gossipsub binding (`seacast-bindings.md` §4): chunks travel as
//! gossipsub messages, and holdings, offers and asks as message-id strings in
//! IDONTWANT, IHAVE and IWANT. Nothing here reads or writes gossipsub's
//! protobuf: a client keeps its own `RPC` codec and hands over a message's
//! data and a control entry's bytes.
//!
//! - [`control`]: the strings.
//! - [`payload`]: the payload's chunk (`seacast-lite.md` §2 `Chunk`), its group
//!   key and message id, and its [`TypeCodec`](seacast_core::TypeCodec).
//! - [`catalog`]: the payload's catalog, over a host that knows the blocks.
//! - [`frame`]: a received `RPC` handed to the node in parts, and a queue entry
//!   written to one.
//!
//! The binding names a group by 32 bytes, so only the payload's groups have
//! strings: those of cell groups are open in the specification.

pub mod catalog;
pub mod control;
pub mod frame;
pub mod payload;

pub use catalog::{PayloadCatalog, PayloadHost, payload_join, payload_params};
pub use control::{
    HOLDING_FIXED, MAX_HAVE_STRING, OFFER_FIXED, WANT_BYTES, holding_string, is_seacast,
    offer_string, read_holding, read_offer, read_want, want_string, want_strings,
};
pub use frame::{Inbound, RpcOut, write_entry};
pub use payload::{
    CHUNK_FIXED, CONTEXT_BYTES, Chunk, MAX_CHUNK_BYTES, MESSAGE_ID_BYTES, MessageId, PAYLOAD,
    PayloadCodec, build_chunk, chunk_id_of, group_key, message_id_of, payload_group, split_chunk,
    split_parts,
};
