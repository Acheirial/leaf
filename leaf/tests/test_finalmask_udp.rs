mod common;

// app(socks) -> (socks)client(chain(finalmask+socks)) -> (chain(finalmask+socks))server(direct) -> echo
//
// A chain runs its actors outwards from the wire: the first one holds what was
// dialled, and every actor after it carries what the one before it produced,
// so the payload belongs last. For UDP that puts the mask first -- it wraps the
// datagram the dispatcher dialled -- and the socks payload last, which is what
// makes the wire between the two instances masked socks5 UDP datagrams. Both
// sides list the mask first: the server takes the mask apart before it reads
// the payload.

const SALAMANDER: &str = r#"{"password":"finalmask-psk"}"#;
const SUDOKU: &str = r#"{"password":"finalmask-test","ascii":"prefer_entropy"}"#;
const NOISE: &str = r#"{"reset":{"from":0,"to":0},"noise":[{"packet":[0,0,0,0]}]}"#;
const HEADER_CUSTOM_UDP: &str =
    r#"{"mode":"prefix","client":[{"packet":[170,187]}],"server":[{"packet":[170,187]}]}"#;

/// The UDP chain, in configuration order.
fn udp_masks() -> String {
    format!(
        r#"[
            {{ "maskType": "salamander", "settings": {salamander:?} }},
            {{ "maskType": "sudoku", "settings": {sudoku:?} }},
            {{ "maskType": "noise", "settings": {noise:?} }},
            {{ "maskType": "header-custom", "settings": {custom:?} }}
        ]"#,
        salamander = SALAMANDER,
        sudoku = SUDOKU,
        noise = NOISE,
        custom = HEADER_CUSTOM_UDP,
    )
}

#[cfg(all(
    feature = "inbound-finalmask",
    feature = "outbound-finalmask",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "inbound-chain",
    feature = "outbound-chain",
    feature = "outbound-direct",
))]
#[test]
fn test_finalmask_udp() -> anyhow::Result<()> {
    let masks = udp_masks();

    let config1 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{ "protocol": "socks", "address": "127.0.0.1", "port": 5311 }}
        ],
        "outbounds": [
            {{ "protocol": "chain", "settings": {{ "actors": ["finalmask", "socks"] }} }},
            {{ "protocol": "socks", "tag": "socks", "settings": {{ "address": "127.0.0.1", "port": 5312 }} }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{ "udp": {masks} }}
            }}
        ]
    }}
    "#,
        masks = masks,
    );

    let config2 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 5312,
                "settings": {{ "actors": ["finalmask", "socks"] }}
            }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{ "udp": {masks} }}
            }},
            {{ "protocol": "socks", "tag": "socks" }}
        ],
        "outbounds": [ {{ "protocol": "direct" }} ]
    }}
    "#,
        masks = masks,
    );

    common::test_configs(vec![config1, config2], "127.0.0.1", 5311)
}
