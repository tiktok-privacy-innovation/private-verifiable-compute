// Copyright 2025 Tiktok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use bytes::Bytes;
use futures::StreamExt;
use futures::channel::mpsc;
use futures::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::task::{Context, Poll};

// Async write wait until enough data is buffered
const WRITE_FLUSH_LIMIT: usize = 1024;
/// Channel slots
const CHANNEL_SLOTS: usize = 8;

// Create a custom AsyncWrite that sends data to the channel
pub struct ChannelWriter {
    flush_limit: usize,
    sender: mpsc::Sender<Bytes>,
    buffer: Vec<u8>,
}

// Create a custom AsyncRead that receives data from the channel
pub struct ChannelReader {
    receiver: mpsc::Receiver<Bytes>,
    current_chunk: Option<Bytes>,
    position: usize,
}

pub fn create_channel_pair_with_size(write_flush_limit: usize) -> (ChannelWriter, ChannelReader) {
    let write_flush_limit = {
        if write_flush_limit == 0 {
            WRITE_FLUSH_LIMIT
        } else {
            write_flush_limit
        }
    };
    let (sender, receiver) = mpsc::channel(CHANNEL_SLOTS);
    let writer = ChannelWriter::new(write_flush_limit, sender);
    let reader = ChannelReader::new(receiver);
    (writer, reader)
}

impl ChannelWriter {
    pub fn new(write_flush_limit: usize, sender: mpsc::Sender<Bytes>) -> Self {
        Self {
            flush_limit: write_flush_limit,
            sender,
            buffer: Vec::new(),
        }
    }
}

impl ChannelReader {
    pub fn new(receiver: mpsc::Receiver<Bytes>) -> Self {
        Self {
            receiver,
            current_chunk: None,
            position: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // Reading into empty buffer: return 0 immediately (no need to touch the channel).
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // If we have no current chunk, try to get one from the receiver
        if self.current_chunk.is_none() {
            match self.receiver.poll_next_unpin(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.current_chunk = Some(chunk);
                    self.position = 0;
                }
                Poll::Ready(None) => {
                    // Channel is closed, no more data
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => {
                    // No data available yet
                    return Poll::Pending;
                }
            }
        }

        // We should have a current chunk now
        if let Some(chunk) = &self.current_chunk {
            let chunk_len = chunk.len();
            let remaining = chunk_len - self.position;

            if remaining == 0 {
                // Current chunk is exhausted, get next one
                self.current_chunk = None;
                return self.poll_read(cx, buf);
            }

            let to_copy = std::cmp::min(remaining, buf.len());
            let chunk_slice = &chunk[self.position..self.position + to_copy];
            buf[..to_copy].copy_from_slice(chunk_slice);
            self.position += to_copy;

            // If we've consumed the entire chunk, clear it
            if self.position >= chunk_len {
                self.current_chunk = None;
                self.position = 0;
            }

            Poll::Ready(Ok(to_copy))
        } else {
            // This shouldn't happen, but handle it gracefully
            Poll::Ready(Ok(0))
        }
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.len() + buf.len() >= self.flush_limit {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    // Channel is ready, take buffer
                    self.buffer.extend_from_slice(buf);
                    let data = Bytes::from(std::mem::take(&mut self.buffer));
                    if let Err(_) = self.sender.start_send(data) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "channel closed",
                        )));
                    }
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "channel closed",
                    )));
                }
                Poll::Pending => {
                    // Channel not ready, can't accept more data
                    return Poll::Pending;
                }
            }
        } else {
            // Won't exceed limit, just buffer the data
            self.buffer.extend_from_slice(buf);
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Send any remaining buffered data
        while !self.buffer.is_empty() {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let data = Bytes::from(std::mem::take(&mut self.buffer));
                    if let Err(_) = self.sender.start_send(data) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "channel closed",
                        )));
                    }
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "channel closed",
                    )));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Flush any remaining data
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                let _ = self.sender.close_channel();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
