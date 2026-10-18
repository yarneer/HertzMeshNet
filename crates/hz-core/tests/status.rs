use hz_core::status::{NodeStatus, RegisteredInfo};
use serde_json::json;

#[test]
fn unregistered_serializes_to_the_stable_minimal_shape() {
    assert_eq!(
        serde_json::to_value(NodeStatus::Unregistered).unwrap(),
        json!({"registered": false})
    );
    let parsed: NodeStatus = serde_json::from_value(json!({"registered": false})).unwrap();
    assert_eq!(parsed, NodeStatus::Unregistered);
}

#[test]
fn registered_roundtrips_identity_fields() {
    let info = RegisteredInfo {
        node_id: "abc123".to_string(),
        name: "host-a".to_string(),
        ipv4: "100.96.0.1".to_string(),
        ipv6: "fd12:3456:789a:0:0:0:6460:1".to_string(),
        tags: vec!["db".to_string()],
        owner_user: None,
        expires_at_unix: Some(1_800_000_000),
    };
    let wire = serde_json::to_value(NodeStatus::Registered(info.clone())).unwrap();
    assert_eq!(
        wire,
        json!({
            "registered": true,
            "node_id": "abc123",
            "name": "host-a",
            "ipv4": "100.96.0.1",
            "ipv6": "fd12:3456:789a:0:0:0:6460:1",
            "tags": ["db"],
            "owner_user": null,
            "expires_at_unix": 1800000000
        })
    );
    let parsed: NodeStatus = serde_json::from_value(wire).unwrap();
    assert_eq!(parsed, NodeStatus::Registered(info));
}
