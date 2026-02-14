// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
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

/// Async write wait until enough data is buffered
const WRITE_FLUSH_LIMIT: usize = 1024;
/// Channel slots
const CHANNEL_SLOTS: usize = 8;

/// Create a custom AsyncWrite that sends data to the channel
pub struct ChannelWriter {
    flush_limit: usize,
    sender: mpsc::Sender<Bytes>,
    buffer: Vec<u8>,
}

/// Create a custom AsyncRead that receives data from the channel
pub struct ChannelReader {
    receiver: mpsc::Receiver<Bytes>,
    current_chunk: Option<Bytes>,
    position: usize,
}

/// Create a channel pair consisting of a ChannelWriter and ChannelReader
/// This is useful for creating a streaming pipe where one end writes
/// and the other end reads the data
pub fn create_channel_pair() -> (ChannelWriter, ChannelReader) {
    create_channel_pair_with_size(WRITE_FLUSH_LIMIT)
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

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
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
                    // Channel is ready then take over the buffer
                    self.buffer.extend_from_slice(buf);
                    let data = Bytes::from(std::mem::take(&mut self.buffer));
                    if let Err(_) = self.sender.start_send(data) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "channel closed (send)",
                        )));
                    }
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "channel closed (poll)",
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
        if !self.buffer.is_empty() {
            match self.sender.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    // Channel is ready then take over the buffer
                    let data = Bytes::from(std::mem::take(&mut self.buffer));
                    if let Err(_) = self.sender.start_send(data) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "channel closed (send)",
                        )));
                    }
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "channel closed (poll)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::AsyncReadExt;
    use futures::io::AsyncWriteExt;

    #[tokio::test]
    async fn async_rw_basic() {
        let (mut writer, mut reader) = create_channel_pair();

        // Test writing and reading data
        let data = b"Hello, world!";
        writer.write_all(data).await.expect("Failed to write data");
        writer.flush().await.expect("Failed to flush writer");

        let mut buffer = vec![0; data.len()];
        reader
            .read_exact(&mut buffer)
            .await
            .expect("Failed to read data");

        assert_eq!(buffer, data);
    }

    #[tokio::test]
    async fn async_rw_buffer_flush() {
        // Test with a small flush limit
        let flush_limit = 8;
        let (mut writer, mut reader) = create_channel_pair_with_size(flush_limit);

        let data = b"1234567890ABCDEF"; // 16 bytes
        writer.write_all(data).await.expect("Failed to write data");
        writer.close().await.expect("Failed to close writer"); // so read_to_end sees EOF

        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .await
            .expect("Failed to read to end");

        assert_eq!(buffer, data);
    }

    #[tokio::test]
    async fn async_rw_custom_buffer_size() {
        // Test with custom buffer sizes
        let (writer1, _) = create_channel_pair();
        assert_eq!(writer1.flush_limit, WRITE_FLUSH_LIMIT);

        let (writer2, _) = create_channel_pair_with_size(64);
        assert_eq!(writer2.flush_limit, 64);

        let (writer3, _) = create_channel_pair_with_size(0); // Should use default
        assert_eq!(writer3.flush_limit, WRITE_FLUSH_LIMIT);
    }

    #[tokio::test]
    async fn async_rw_channel_closure() {
        let (mut writer, mut reader) = create_channel_pair();

        // Write some data
        writer
            .write_all(b"test data")
            .await
            .expect("Failed to write");
        writer.close().await.expect("Failed to close writer");

        // Should be able to read the remaining data
        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .await
            .expect("Failed to read");

        assert_eq!(buffer, b"test data");

        // Reading from closed channel should return Ok(0)
        let mut empty_buffer = vec![0; 10];
        let n = reader
            .read(&mut empty_buffer)
            .await
            .expect("Failed to read from closed channel");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn async_rw_edge_cases() {
        let (mut writer, mut reader) = create_channel_pair_with_size(4);

        // Test writing zero-length data
        let zero_len_data: &[u8] = &[];
        let n = writer
            .write(zero_len_data)
            .await
            .expect("Failed to write zero-length data");
        assert_eq!(n, 0);

        // Test flushing empty buffer
        writer.flush().await.expect("Failed to flush empty buffer");

        // Test reading into empty buffer
        let empty_buffer: &mut [u8] = &mut [];
        let n = reader
            .read(empty_buffer)
            .await
            .expect("Failed to read into empty buffer");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn async_rw_fast_writer_slow_reader() {
        let (mut writer, mut reader) = create_channel_pair_with_size(16);

        let num_chunks = 20;

        let writer_task = tokio::spawn(async move {
            let mut idx: i32 = 0;

            for i in 0..num_chunks {
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                // random chunk size
                let sze = (seed as usize % 512) + 1;
                let mut chunk = vec![i as u8; sze];
                for j in 0..sze {
                    chunk[j] = idx as u8;
                    idx = idx + 1;
                }
                writer
                    .write_all(&chunk)
                    .await
                    .expect("Failed to write chunk");

                // Spawn fast writer task write every 1ms
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }

            writer.close().await.expect("Failed to close writer");
        });

        // Spawn slow reader task: read 128B every 10ms
        let reader_task = tokio::spawn(async move {
            let mut buffer = vec![0; 128];
            let mut idx: i32 = 0;

            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => {
                        for i in 0..n {
                            assert_eq!(buffer[i], idx as u8);
                            idx += 1;
                        }
                        // Spawn slow reader task write every 10ms
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        panic!("Reader error: {}", e);
                    }
                }
            }
        });

        // Wait for both tasks to complete
        writer_task.await.expect("Writer task failed");
        reader_task.await.expect("Reader task failed");
    }

    #[tokio::test]
    async fn async_rw_large_data_transfer() {
        let (mut writer, mut reader) = create_channel_pair_with_size(32);

        // Test with large data
        let data = vec![0x42; 1024];
        writer
            .write_all(&data)
            .await
            .expect("Failed to write large data");
        writer.close().await.expect("Failed to close");

        let mut buffer = Vec::new();
        reader
            .read_to_end(&mut buffer)
            .await
            .expect("Failed to read large data");

        assert_eq!(buffer, data);
    }
}
