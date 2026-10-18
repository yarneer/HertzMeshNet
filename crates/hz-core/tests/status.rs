use hz_core::status::NodeStatus;
use serde_json::json;

#[test]
fn node_status_serializes_to_the_stable_wire_shape() {
    assert_eq!(
        serde_json::to_value(NodeStatus::Unregistered).unwrap(),
        json!({"registered": false})
    );
    assert_eq!(
        serde_json::to_value(NodeStatus::Registered(Default::default())).unwrap(),
        json!({"registered": true})
    );
    let parsed: NodeStatus = serde_json::from_value(json!({"registered": false})).unwrap();
    assert_eq!(parsed, NodeStatus::Unregistered);
}
