//! Node 侧的 Relay 客户端（FR-9）：TLS + Machine-Key 挑战接入 RelayStream，
//! 对上层暴露 `send_datagram(dst, payload)` 与入站数据报 channel。
//! 与 Coordination Server 相同的挑战语义：nonce 自取、Machine Key 签名，
//! 验证由 Relay 代理给 Coordination Server（RelayCheckNode）。

use std::sync::{Arc, Mutex as StdMutex};

use anyhow::Context;
use ed25519_dalek::Signer;
use hz_proto::relay_client::RelayClient as RelayGrpcClient;
use hz_proto::relay_frame;
use hz_proto::{RelayData, RelayFrame, RelayHello};
use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::coord_client::connect_tls_channel;
use crate::keys::KeyStore;

/// 出站帧队列深度。满时 send_datagram 拒绝并告警（WireGuard 会重传）。
const OUTBOUND_DEPTH: usize = 256;
/// 入站数据报队列深度。消费者（SocketEngine 的中继泵）持续排空。
const INBOUND_DEPTH: usize = 256;

pub struct RelayClient {
    outbound: mpsc::Sender<RelayFrame>,
    incoming: StdMutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

/// 连接 Relay 并完成挑战接入。ca_pem 为 Some 时信任该私有 CA（自签部署），
/// 地址必须带 scheme（https://… 或测试内网 http://…）。
pub async fn connect_relay(
    keys: &Arc<KeyStore>,
    node_id: &str,
    relay_addr: &str,
    ca_pem: Option<&str>,
) -> anyhow::Result<RelayClient> {
    let channel = connect_tls_channel(relay_addr, ca_pem)
        .await
        .with_context(|| format!("连接 Relay {relay_addr} 失败"))?;
    let mut client = RelayGrpcClient::new(channel);

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let hello = RelayHello {
        node_id: node_id.to_owned(),
        node_key_pub: keys.node_public().to_vec(),
        machine_key_pub: keys.machine_public().to_vec(),
        challenge_nonce: nonce.to_vec(),
        challenge_signature: keys.machine().sign(&nonce).to_bytes().to_vec(),
    };

    let (frame_tx, frame_rx) = mpsc::channel::<RelayFrame>(OUTBOUND_DEPTH);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_DEPTH);
    frame_tx
        .send(RelayFrame {
            kind: Some(relay_frame::Kind::Hello(hello)),
        })
        .await
        .context("relay stream queue closed before hello")?;
    let stream = client
        .relay_stream(ReceiverStream::new(frame_rx))
        .await
        .with_context(|| format!("打开 RelayStream 失败：{relay_addr}"))?
        .into_inner();

    tokio::spawn(pump_stream(stream, inbound_tx));
    tracing::info!(%relay_addr, node_id, "relay stream opened");
    Ok(RelayClient {
        outbound: frame_tx,
        incoming: StdMutex::new(Some(inbound_rx)),
    })
}

async fn pump_stream(mut stream: Streaming<RelayFrame>, inbound: mpsc::Sender<Vec<u8>>) {
    loop {
        match stream.message().await {
            Ok(Some(frame)) => match frame.kind {
                Some(relay_frame::Kind::Data(data)) => {
                    if inbound.send(data.payload).await.is_err() {
                        break;
                    }
                }
                Some(relay_frame::Kind::Error(error)) => {
                    tracing::warn!(
                        code = %error.code,
                        message = %error.message,
                        "relay returned error, relay transport down until reconnect"
                    );
                    break;
                }
                Some(relay_frame::Kind::Hello(_)) => {
                    tracing::warn!("unexpected hello frame from relay, closing stream");
                    break;
                }
                None => {}
            },
            Ok(None) => {
                tracing::warn!("relay stream closed by server");
                break;
            }
            Err(error) => {
                tracing::warn!(%error, "relay stream error");
                break;
            }
        }
    }
}

impl RelayClient {
    /// 发一个数据报到指定 Node（按 node id 寻址）。流已断开时记录并丢弃，
    /// 由上层路径重估（#8）负责恢复。
    pub async fn send_datagram(&self, dst_node_id: &str, payload: Vec<u8>) {
        let frame = RelayFrame {
            kind: Some(relay_frame::Kind::Data(RelayData {
                dst_node_id: dst_node_id.to_owned(),
                payload,
            })),
        };
        if self.outbound.send(frame).await.is_err() {
            tracing::warn!(dst = %dst_node_id, "relay outbound closed, dropping datagram");
        }
    }

    /// 取走入站数据报接收端。只能取一次，交给 SocketEngine 的中继泵消费。
    pub fn take_incoming(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.incoming
            .lock()
            .expect("relay incoming poisoned")
            .take()
    }
}
