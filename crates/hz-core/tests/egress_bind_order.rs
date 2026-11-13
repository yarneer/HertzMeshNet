//! 外层 UDP socket 的出口绑定必须在 bind(2) 之前生效：macOS 上 bind 之后才
//! 设的 IP_BOUND_IF / IPV6_BOUND_IF 不起作用，第三方 TUN 接管默认路由时外层
//! 包会被送进 TUN（发往公网 EHOSTUNREACH）。
//! 保护钩子是进程级全局状态，所以单独成一个测试二进制、只有一个测试函数。

use std::os::fd::{BorrowedFd, RawFd};
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use x25519_dalek::StaticSecret;

fn local_port(fd: RawFd) -> u16 {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    socket2::SockRef::from(&fd)
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_socket())
        .map_or(0, |addr| addr.port())
}

#[tokio::test]
async fn outer_udp_sockets_are_bound_to_egress_before_bind() {
    let ports_at_protect = Arc::new(Mutex::new(Vec::new()));
    let seen = ports_at_protect.clone();
    hz_core::netif::set_socket_protector(Arc::new(move |fd| {
        seen.lock().unwrap().push(local_port(fd));
        Some("test-egress".to_string())
    }));
    let take = || std::mem::take(&mut *ports_at_protect.lock().unwrap());

    let engine = hz_core::wire::SocketEngine::bind(StaticSecret::random_from_rng(OsRng), 0)
        .await
        .unwrap();
    assert_eq!(take(), vec![0], "WireGuard socket：钩子调用时还没绑端口");
    assert_ne!(engine.local_addr().port(), 0, "之后照常绑上了端口");

    for local in ["0.0.0.0:0", "[::]:0"] {
        let socket = hz_core::netif::bind_outer_udp(local.parse().unwrap(), true).unwrap();
        assert_eq!(take(), vec![0], "{local}：钩子调用时还没绑端口");
        assert_ne!(socket.local_addr().unwrap().port(), 0);
    }
}
