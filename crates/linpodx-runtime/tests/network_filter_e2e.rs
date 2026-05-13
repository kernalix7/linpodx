//! Integration: spin up the egress DNS filter and assert that a disallowed query gets
//! `NXDOMAIN`. Marked `#[ignore]` because hermetic CI sandboxes sometimes refuse loopback
//! UDP binds.

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use linpodx_runtime::network_filter;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
#[ignore]
async fn nxdomain_for_disallowed_host() {
    let handle = network_filter::start(vec!["allowed.test".into()], None)
        .await
        .expect("start filter");
    let server = handle.local_addr();

    let mut msg = Message::new();
    msg.set_id(0xbeef);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(
        Name::from_str("blocked.test.").unwrap(),
        RecordType::A,
    ));

    let bytes = msg.to_vec().unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&bytes, server).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv error");
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
}
