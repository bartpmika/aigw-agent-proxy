//! Response body helpers: full bodies, streamed bodies, and a stream wrapper
//! that captures what passed through for logging, then reports on drop.

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use std::collections::VecDeque;
use std::io;

pub type Body = UnsyncBoxBody<Bytes, io::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed_unsync()
}

pub fn empty() -> Body {
    full(Bytes::new())
}

pub fn from_stream<S>(stream: S) -> Body
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    StreamBody::new(stream.map(|r| r.map(Frame::data))).boxed_unsync()
}

const TAIL: usize = 64 * 1024;

/// Keeps up to `head_cap` bytes from the start plus the last `TAIL` bytes,
/// which is where SSE usage lives. Chunks are kept by reference (no copies).
pub struct Capture {
    head: Vec<Bytes>,
    head_len: usize,
    tail: VecDeque<Bytes>,
    tail_len: usize,
    head_cap: usize,
    truncated: bool,
    on_done: Option<Box<dyn FnOnce(Vec<u8>, bool) + Send>>,
}

impl Capture {
    pub fn new(head_cap: usize, on_done: impl FnOnce(Vec<u8>, bool) + Send + 'static) -> Self {
        Self {
            head: Vec::new(),
            head_len: 0,
            tail: VecDeque::new(),
            tail_len: 0,
            head_cap,
            truncated: false,
            on_done: Some(Box::new(on_done)),
        }
    }

    pub fn push(&mut self, chunk: &Bytes) {
        if chunk.is_empty() {
            return;
        }
        if !self.truncated && self.head_len + chunk.len() <= self.head_cap {
            self.head_len += chunk.len();
            self.head.push(chunk.clone());
            return;
        }
        self.truncated = true;
        self.tail_len += chunk.len();
        self.tail.push_back(chunk.clone());
        while self.tail_len - self.tail.front().map_or(0, Bytes::len) >= TAIL {
            self.tail_len -= self.tail.pop_front().map_or(0, |b| b.len());
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let Some(done) = self.on_done.take() else { return };
        let mut bytes = Vec::with_capacity(self.head_len + if self.truncated { self.tail_len + 1 } else { 0 });
        for b in &self.head {
            bytes.extend_from_slice(b);
        }
        if self.truncated {
            // Start the tail on a fresh SSE line.
            let tail: Vec<u8> = self.tail.iter().flat_map(|b| b.iter().copied()).collect();
            let start = tail.iter().position(|b| *b == b'\n').map_or(0, |p| p + 1);
            bytes.push(b'\n');
            bytes.extend_from_slice(&tail[start..]);
        }
        done(bytes, self.truncated);
    }
}
