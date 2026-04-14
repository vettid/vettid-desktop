//! Microphone capture → Opus → WebRTC audio track.
//!
//! ## Send-safety constraints
//!
//! cpal's `Stream` type is `!Send` on macOS (CoreAudio binds the audio
//! thread to a specific OS thread), so we cannot store it in
//! `Arc<CallSession>` directly — that would propagate `!Send` up through
//! `AppState` and break every `tokio::spawn` site that touches state.
//!
//! Instead we own the stream on a dedicated OS thread that we spawn from
//! [`start_capture`]. The handle we return is just a `JoinHandle` plus a
//! shutdown signal; the cpal stream stays trapped inside the thread where
//! its `!Send` is harmless.
//!
//! ## Pipeline
//!
//! 1. cpal callback (audio OS thread) → mpsc → encoder Tokio task
//! 2. Encoder task buffers into 20 ms frames at 48 kHz mono
//! 3. Each frame goes through libopus (Voip preset)
//! 4. Encoded bytes write to the WebRTC `TrackLocalStaticSample`, which
//!    paces the RTP send rate via the supplied frame duration.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate};
use tokio::sync::mpsc;
use webrtc::media::Sample;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_remote::TrackRemote;

/// 48 kHz × 20 ms = 960 samples per Opus frame at 48 kHz mono.
const OPUS_SAMPLE_RATE: u32 = 48_000;
const OPUS_FRAME_MS: usize = 20;
const OPUS_FRAME_SAMPLES: usize = OPUS_SAMPLE_RATE as usize / 1000 * OPUS_FRAME_MS;

/// Returned by [`start_capture`]. Drop it to stop the cpal stream and join
/// the audio OS thread.
pub struct CaptureHandle {
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            // Best-effort join. If the audio thread is wedged we don't want
            // to block teardown of the call indefinitely.
            let _ = handle.join();
        }
    }
}

/// Open the default input device and start streaming Opus frames to `track`.
///
/// The call is non-blocking — capture runs on a dedicated OS thread and an
/// async encoder task. Drop the returned handle to stop both.
pub fn start_capture(
    track: Arc<TrackLocalStaticSample>,
) -> Result<CaptureHandle, String> {
    let (sample_tx, sample_rx) = mpsc::unbounded_channel::<Vec<f32>>();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn the encoder task immediately so we don't drop samples while the
    // audio thread is starting up.
    spawn_encoder_task(sample_rx, track);

    let shutdown_for_thread = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("vettid-audio-capture".to_string())
        .spawn(move || run_capture_thread(sample_tx, shutdown_for_thread))
        .map_err(|e| format!("spawn audio thread: {}", e))?;

    Ok(CaptureHandle {
        shutdown,
        thread: Some(thread),
    })
}

/// Body of the dedicated audio thread. Owns the !Send cpal stream until
/// shutdown is signalled.
fn run_capture_thread(
    sample_tx: mpsc::UnboundedSender<Vec<f32>>,
    shutdown: Arc<AtomicBool>,
) {
    let host = cpal::default_host();
    let device = match host.default_input_device() {
        Some(d) => d,
        None => {
            log::error!("Audio capture: no default input device");
            return;
        }
    };

    log::info!(
        "Audio capture device: {}",
        device.name().unwrap_or_else(|_| "<unknown>".to_string()),
    );

    let supported = match device.default_input_config() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Audio capture: query input config failed: {}", e);
            return;
        }
    };

    let stream_config = cpal::StreamConfig {
        channels: 1,
        sample_rate: SampleRate(OPUS_SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default,
    };

    let err_cb = |err| log::warn!("cpal stream error: {}", err);

    let stream_result = match supported.sample_format() {
        SampleFormat::F32 => {
            let tx = sample_tx.clone();
            device.build_input_stream(
                &stream_config,
                move |data: &[f32], _| {
                    let _ = tx.send(data.to_vec());
                },
                err_cb,
                None,
            )
        }
        SampleFormat::I16 => {
            let tx = sample_tx.clone();
            device.build_input_stream(
                &stream_config,
                move |data: &[i16], _| {
                    let buf: Vec<f32> = data
                        .iter()
                        .map(|s| *s as f32 / i16::MAX as f32)
                        .collect();
                    let _ = tx.send(buf);
                },
                err_cb,
                None,
            )
        }
        SampleFormat::U16 => {
            let tx = sample_tx.clone();
            device.build_input_stream(
                &stream_config,
                move |data: &[u16], _| {
                    let buf: Vec<f32> = data
                        .iter()
                        .map(|s| (*s as f32 - 32768.0) / 32768.0)
                        .collect();
                    let _ = tx.send(buf);
                },
                err_cb,
                None,
            )
        }
        other => {
            log::error!("Audio capture: unsupported sample format {:?}", other);
            return;
        }
    };

    let stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log::error!("Audio capture: build_input_stream failed: {}", e);
            return;
        }
    };

    if let Err(e) = stream.play() {
        log::error!("Audio capture: stream.play failed: {}", e);
        return;
    }
    log::info!("Audio capture started: 48 kHz mono, 20 ms Opus frames");

    // Park here until shutdown. We can't block on the stream itself
    // (it's just a handle) — the cpal callbacks fire on its own internal
    // thread. We're the keeper-alive.
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    drop(stream);
    log::info!("Audio capture stopped");
}

/// Re-buffer arbitrary-sized cpal callbacks into 20 ms chunks, encode each
/// with Opus, and write to the WebRTC track.
fn spawn_encoder_task(
    mut sample_rx: mpsc::UnboundedReceiver<Vec<f32>>,
    track: Arc<TrackLocalStaticSample>,
) {
    tokio::spawn(async move {
        let mut encoder = match opus::Encoder::new(
            OPUS_SAMPLE_RATE,
            opus::Channels::Mono,
            opus::Application::Voip,
        ) {
            Ok(e) => e,
            Err(e) => {
                log::error!("Failed to init Opus encoder: {}", e);
                return;
            }
        };

        let mut buffer: Vec<f32> = Vec::with_capacity(OPUS_FRAME_SAMPLES * 2);
        let mut output = vec![0u8; 4000]; // generous; Opus frames are typically <200 bytes

        while let Some(chunk) = sample_rx.recv().await {
            buffer.extend_from_slice(&chunk);

            // Emit as many full 20 ms frames as we can before going back
            // for more samples — keeps end-to-end latency at one frame.
            while buffer.len() >= OPUS_FRAME_SAMPLES {
                let frame: Vec<f32> = buffer.drain(..OPUS_FRAME_SAMPLES).collect();
                let encoded_len = match encoder.encode_float(&frame, &mut output) {
                    Ok(n) => n,
                    Err(e) => {
                        log::warn!("Opus encode failed: {}", e);
                        continue;
                    }
                };
                let sample = Sample {
                    data: bytes::Bytes::copy_from_slice(&output[..encoded_len]),
                    duration: Duration::from_millis(OPUS_FRAME_MS as u64),
                    ..Default::default()
                };
                if let Err(e) = track.write_sample(&sample).await {
                    log::warn!("write_sample failed: {}", e);
                }
            }
        }

        log::debug!("Audio encoder task ended");
    });
}

// ---------------------------------------------------------------------------
// Playback (peer audio → speakers)
// ---------------------------------------------------------------------------

/// Returned by [`start_playback`]. Drop it to stop the cpal output stream
/// and join the audio thread.
pub struct PlaybackHandle {
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PlaybackHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Pull RTP packets from `track`, decode Opus, and play through the default
/// output device.
///
/// Symmetric to [`start_capture`]: a Tokio task reads/decodes, an OS thread
/// owns the (!Send) cpal output stream, and an mpsc bridges them. The
/// playback shared buffer is a Mutex<VecDeque<f32>> rather than another
/// mpsc because the cpal output callback needs random-access drain to
/// match its requested frame size.
pub fn start_playback(
    track: Arc<TrackRemote>,
) -> Result<PlaybackHandle, String> {
    use std::collections::VecDeque;

    let buffer: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::with_capacity(
        OPUS_SAMPLE_RATE as usize, // ~1s of buffered audio
    )));
    let shutdown = Arc::new(AtomicBool::new(false));

    spawn_decoder_task(track, buffer.clone(), shutdown.clone());

    let buffer_for_thread = buffer.clone();
    let shutdown_for_thread = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("vettid-audio-playback".to_string())
        .spawn(move || run_playback_thread(buffer_for_thread, shutdown_for_thread))
        .map_err(|e| format!("spawn playback thread: {}", e))?;

    Ok(PlaybackHandle {
        shutdown,
        thread: Some(thread),
    })
}

fn run_playback_thread(
    buffer: Arc<Mutex<std::collections::VecDeque<f32>>>,
    shutdown: Arc<AtomicBool>,
) {
    let host = cpal::default_host();
    let device = match host.default_output_device() {
        Some(d) => d,
        None => {
            log::error!("Audio playback: no default output device");
            return;
        }
    };

    log::info!(
        "Audio playback device: {}",
        device.name().unwrap_or_else(|_| "<unknown>".to_string()),
    );

    let stream_config = cpal::StreamConfig {
        channels: 1,
        sample_rate: SampleRate(OPUS_SAMPLE_RATE),
        buffer_size: cpal::BufferSize::Default,
    };
    let supported = match device.default_output_config() {
        Ok(c) => c,
        Err(e) => {
            log::error!("Audio playback: query output config failed: {}", e);
            return;
        }
    };

    let err_cb = |err| log::warn!("cpal output stream error: {}", err);

    let buffer_for_cb = buffer.clone();
    let stream_result = match supported.sample_format() {
        SampleFormat::F32 => device.build_output_stream(
            &stream_config,
            move |out: &mut [f32], _| fill_output(out, &buffer_for_cb, |s| s),
            err_cb,
            None,
        ),
        SampleFormat::I16 => device.build_output_stream(
            &stream_config,
            move |out: &mut [i16], _| {
                fill_output(out, &buffer_for_cb, |s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16);
            },
            err_cb,
            None,
        ),
        SampleFormat::U16 => device.build_output_stream(
            &stream_config,
            move |out: &mut [u16], _| {
                fill_output(out, &buffer_for_cb, |s| {
                    ((s.clamp(-1.0, 1.0) * 32767.0) + 32768.0) as u16
                });
            },
            err_cb,
            None,
        ),
        other => {
            log::error!("Audio playback: unsupported sample format {:?}", other);
            return;
        }
    };

    let stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log::error!("Audio playback: build_output_stream failed: {}", e);
            return;
        }
    };

    if let Err(e) = stream.play() {
        log::error!("Audio playback: stream.play failed: {}", e);
        return;
    }
    log::info!("Audio playback started");

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    drop(stream);
    log::info!("Audio playback stopped");
}

/// Drain up to `out.len()` samples from the shared buffer; any shortfall is
/// padded with silence so the audio device keeps clocking.
fn fill_output<S: Copy + Default>(
    out: &mut [S],
    buffer: &Arc<Mutex<std::collections::VecDeque<f32>>>,
    convert: impl Fn(f32) -> S,
) {
    let mut buf = buffer.lock().unwrap_or_else(|p| p.into_inner());
    for slot in out.iter_mut() {
        *slot = match buf.pop_front() {
            Some(s) => convert(s),
            None => S::default(),
        };
    }
}

fn spawn_decoder_task(
    track: Arc<TrackRemote>,
    buffer: Arc<Mutex<std::collections::VecDeque<f32>>>,
    shutdown: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut decoder = match opus::Decoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to init Opus decoder: {}", e);
                return;
            }
        };

        // 120ms (6 × 20ms) is the largest Opus frame size at 48 kHz; size for
        // that to avoid mid-call reallocs.
        let mut decoded = vec![0f32; OPUS_FRAME_SAMPLES * 6];

        while !shutdown.load(Ordering::SeqCst) {
            let (rtp_packet, _attrs) = match track.read_rtp().await {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("read_rtp ended: {}", e);
                    break;
                }
            };
            let payload = rtp_packet.payload;
            if payload.is_empty() {
                continue;
            }
            let n = match decoder.decode_float(&payload, &mut decoded, false) {
                Ok(n) => n,
                Err(e) => {
                    log::warn!("Opus decode failed: {}", e);
                    continue;
                }
            };
            // Push into the shared buffer; cap at ~500ms so we don't grow
            // unboundedly if playback stalls.
            let mut buf = buffer.lock().unwrap_or_else(|p| p.into_inner());
            if buf.len() > OPUS_SAMPLE_RATE as usize / 2 {
                let drop_count = buf.len() - OPUS_SAMPLE_RATE as usize / 2;
                buf.drain(..drop_count);
            }
            buf.extend(decoded[..n].iter().copied());
        }

        log::debug!("Audio decoder task ended");
    });
}
