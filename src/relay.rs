//! 客户端与服务端共用的 TCP 双向转发逻辑

use crate::RELAY_BUFFER_SIZE;
use crate::user_manager::UserLimiter;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

/// 关闭写端（发送 FIN / TLS close_notify）的最长等待时间，防止对端不读导致卡死
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// 整条隧道双方向完全无数据往来时的默认空闲超时（防止弱网半开连接永久占用配额）
pub const DEFAULT_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// 写入并立即 flush。
///
/// tokio-rustls 的 `write_all` 只保证数据进入 rustls 发送缓冲，不 flush 就可能
/// 滞留不发；所以写 TLS 时每次都要显式 flush。
pub async fn write_and_flush<W>(writer: &mut W, data: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(data).await?;
    writer.flush().await
}

/// 单向转发：`reader` -> `writer`
///
/// - 读端正常 EOF：只把半关闭（FIN）传给写端，不影响另一方向。很多客户端
///   "请求发完就半关闭"，目标也常要靠 FIN 才回包，不能因此掐断整条隧道。
/// - 出错：取消 `cancel`，连带拆除另一方向。
/// - `cancel` 被取消：立即停止。
pub async fn relay_one_way<R, W, F>(
    reader: R,
    writer: W,
    limiter: Option<&UserLimiter>,
    cancel: &CancellationToken,
    on_bytes: F,
    direction: &str,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(usize),
{
    relay_one_way_tracked(reader, writer, limiter, cancel, None, on_bytes, direction).await;
}

/// 带活跃时间戳更新的单向转发
pub async fn relay_one_way_tracked<R, W, F>(
    mut reader: R,
    mut writer: W,
    limiter: Option<&UserLimiter>,
    cancel: &CancellationToken,
    activity: Option<(&Instant, &AtomicU64)>,
    mut on_bytes: F,
    direction: &str,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(usize),
{
    let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
    // 低速限流时按 burst 限制单次读取大小，避免一次读满 32KB 后长时间停顿再突发写出
    let read_cap = limiter.map_or(buf.len(), |l| buf.len().min(l.burst()));
    let result = cancel
        .run_until_cancelled(async {
            loop {
                let n = reader.read(&mut buf[..read_cap]).await?;
                if n == 0 {
                    return Ok::<_, io::Error>(());
                }
                if let Some((epoch, last_ms)) = activity {
                    last_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
                if let Some(limiter) = limiter {
                    limiter.consume(n).await;
                }
                write_and_flush(&mut writer, &buf[..n]).await?;
                if let Some((epoch, last_ms)) = activity {
                    last_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
                on_bytes(n);
            }
        })
        .await;

    if let Some(Err(e)) = result {
        error!("Relay {} error: {}", direction, e);
        cancel.cancel();
    }
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, writer.shutdown()).await;
}

/// 在同一个任务内完成两个方向的转发，两个方向都结束后才返回。
///
/// `a` 一般是发起方（本地应用 / 代理客户端），`b` 是对端（代理服务端 / 目标）。
#[allow(clippy::too_many_arguments)]
pub async fn relay_bidirectional<AR, AW, BR, BW, F1, F2>(
    a_reader: AR,
    a_writer: AW,
    b_reader: BR,
    b_writer: BW,
    limiter: Option<&UserLimiter>,
    cancel: &CancellationToken,
    on_a_to_b: F1,
    on_b_to_a: F2,
) where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
    F1: FnMut(usize),
    F2: FnMut(usize),
{
    relay_bidirectional_with_idle(
        a_reader,
        a_writer,
        b_reader,
        b_writer,
        limiter,
        cancel,
        DEFAULT_RELAY_IDLE_TIMEOUT,
        on_a_to_b,
        on_b_to_a,
    )
    .await;
}

/// 带连接级双向空闲超时的转发：只有上行和下行同时无数据超过 `idle_timeout` 才会触发超时关闭，
/// 单向持续大文件下载不会误触发超时。
#[allow(clippy::too_many_arguments)]
pub async fn relay_bidirectional_with_idle<AR, AW, BR, BW, F1, F2>(
    a_reader: AR,
    a_writer: AW,
    b_reader: BR,
    b_writer: BW,
    limiter: Option<&UserLimiter>,
    cancel: &CancellationToken,
    idle_timeout: Duration,
    on_a_to_b: F1,
    on_b_to_a: F2,
) where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
    F1: FnMut(usize),
    F2: FnMut(usize),
{
    let epoch = Instant::now();
    let last_active_ms = AtomicU64::new(0);
    let done = CancellationToken::new();

    let transfer = async {
        tokio::join!(
            relay_one_way_tracked(
                a_reader,
                b_writer,
                limiter,
                cancel,
                Some((&epoch, &last_active_ms)),
                on_a_to_b,
                "upload",
            ),
            relay_one_way_tracked(
                b_reader,
                a_writer,
                limiter,
                cancel,
                Some((&epoch, &last_active_ms)),
                on_b_to_a,
                "download",
            ),
        );
        done.cancel();
    };

    let watchdog = async {
        let idle_ms = idle_timeout.as_millis().max(1) as u64;
        loop {
            let now_ms = epoch.elapsed().as_millis() as u64;
            let silent_ms = now_ms.saturating_sub(last_active_ms.load(Ordering::Relaxed));
            if silent_ms >= idle_ms {
                debug!("Relay idle for {:?}, closing tunnel", idle_timeout);
                cancel.cancel();
                break;
            }
            let wait = Duration::from_millis(idle_ms - silent_ms);
            if done
                .run_until_cancelled(tokio::time::sleep(wait))
                .await
                .is_none()
            {
                break;
            }
        }
    };

    tokio::join!(transfer, watchdog);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_half_close_keeps_other_direction() {
        // a 侧发完数据后半关闭，b 侧仍然可以继续回包
        let (mut app, a) = duplex(1024);
        let (b, mut target) = duplex(1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let cancel = CancellationToken::new();

        let relay = relay_bidirectional(a_r, a_w, b_r, b_w, None, &cancel, |_| {}, |_| {});
        let peers = async {
            app.write_all(b"ping").await.unwrap();
            app.shutdown().await.unwrap();

            let mut req = Vec::new();
            target.read_to_end(&mut req).await.unwrap();
            assert_eq!(req, b"ping");
            target.write_all(b"pong").await.unwrap();
            target.shutdown().await.unwrap();

            let mut resp = Vec::new();
            app.read_to_end(&mut resp).await.unwrap();
            assert_eq!(resp, b"pong");
        };
        tokio::join!(relay, peers);
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_low_rate_limit_streams_in_burst_sized_chunks() {
        // 限速 2KB/s 发送 8KB 数据时，首块 2KB 应立即到达对端，而不是攒满 32KB 缓冲才发
        let limiter = UserLimiter::new(2048).unwrap();
        let (mut app, a) = duplex(64 * 1024);
        let (b, mut target) = duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let cancel = CancellationToken::new();

        let relay = tokio::spawn(async move {
            relay_bidirectional(a_r, a_w, b_r, b_w, Some(&limiter), &cancel, |_| {}, |_| {}).await;
        });

        app.write_all(&vec![b'x'; 8192]).await.unwrap();
        let mut first_chunk = [0u8; 2048];
        tokio::time::timeout(
            Duration::from_millis(200),
            target.read_exact(&mut first_chunk),
        )
        .await
        .expect("first burst-sized chunk should arrive without multi-second stall")
        .unwrap();
        assert_eq!(&first_chunk, &[b'x'; 2048]);

        relay.abort();
    }

    #[tokio::test]
    async fn test_idle_timeout_closes_silent_tunnel_but_keeps_unidirectional_stream() {
        // 1. 双方向完全静默时，达到 idle_timeout 应自动退出并取消
        let (_app, a) = duplex(1024);
        let (b, _target) = duplex(1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let cancel = CancellationToken::new();

        tokio::time::timeout(
            Duration::from_millis(500),
            relay_bidirectional_with_idle(
                a_r,
                a_w,
                b_r,
                b_w,
                None,
                &cancel,
                Duration::from_millis(60),
                |_| {},
                |_| {},
            ),
        )
        .await
        .expect("silent tunnel should be closed by idle watchdog");
        assert!(cancel.is_cancelled());

        // 2. 只有下行持续传输、上行完全静默时，绝不能误判为空闲超时
        let (mut app, a) = duplex(1024);
        let (b, mut target) = duplex(1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let cancel2 = CancellationToken::new();

        let relay = relay_bidirectional_with_idle(
            a_r,
            a_w,
            b_r,
            b_w,
            None,
            &cancel2,
            Duration::from_millis(80),
            |_| {},
            |_| {},
        );
        let peers = async {
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(35)).await;
                target.write_all(b"chunk").await.unwrap();
            }
            target.shutdown().await.unwrap();
            app.shutdown().await.unwrap();

            let mut received = Vec::new();
            app.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"chunkchunkchunkchunk");
        };
        tokio::join!(relay, peers);
        assert!(!cancel2.is_cancelled());
    }
}
