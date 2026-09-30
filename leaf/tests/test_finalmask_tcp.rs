mod common;

// app(socks) -> (socks)client(chain(finalmask+socks)) -> (chain(finalmask+socks))server(direct) -> echo
//
// The finalmask actor sits below the socks payload: on the client it wraps the
// dialled stream first, on the server it unwraps the accepted stream first.
// The chain therefore carries the whole 2 MiB payload through the configured
// mask chain (a TCP fragmentation mask and a sudoku stream mask here).

const FRAGMENT: &str = r#"{"packets":"1-1","length":{"from":512,"to":1024}}"#;
const SUDOKU: &str = r#"{"password":"finalmask-test","ascii":"prefer_entropy"}"#;

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
fn test_finalmask_tcp() -> anyhow::Result<()> {
    let config1 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{ "protocol": "socks", "address": "127.0.0.1", "port": 5301 }}
        ],
        "outbounds": [
            {{ "protocol": "chain", "settings": {{ "actors": ["finalmask", "socks"] }} }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{
                    "tcp": [
                        {{ "maskType": "fragment", "settings": {fragment:?} }},
                        {{ "maskType": "sudoku", "settings": {sudoku:?} }}
                    ]
                }}
            }},
            {{ "protocol": "socks", "tag": "socks", "settings": {{ "address": "127.0.0.1", "port": 5302 }} }}
        ]
    }}
    "#,
        fragment = FRAGMENT,
        sudoku = SUDOKU,
    );

    let config2 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 5302,
                "settings": {{ "actors": ["finalmask", "socks"] }}
            }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{
                    "tcp": [
                        {{ "maskType": "fragment", "settings": {fragment:?} }},
                        {{ "maskType": "sudoku", "settings": {sudoku:?} }}
                    ]
                }}
            }},
            {{ "protocol": "socks", "tag": "socks" }}
        ],
        "outbounds": [ {{ "protocol": "direct" }} ]
    }}
    "#,
        fragment = FRAGMENT,
        sudoku = SUDOKU,
    );

    // 2 MiB of random bytes in both directions, compared by SHA-256.
    common::test_tcp_transfering_reliability_on_configs(vec![config1, config2], "127.0.0.1", 5301)
}

// The header-custom TCP mask runs a client/server sequence handshake before
// the payload; this checks the chain end to end with it in the list.

const HEADER_CUSTOM_TCP: &str =
    r#"{"clients":[[{"packet":[1,2,3,4]}]],"servers":[[{"packet":[5,6,7,8]}]]}"#;

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
fn test_finalmask_tcp_header_custom() -> anyhow::Result<()> {
    let config1 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{ "protocol": "socks", "address": "127.0.0.1", "port": 5303 }}
        ],
        "outbounds": [
            {{ "protocol": "chain", "settings": {{ "actors": ["finalmask", "socks"] }} }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{
                    "tcp": [
                        {{ "maskType": "header-custom", "settings": {custom:?} }}
                    ]
                }}
            }},
            {{ "protocol": "socks", "tag": "socks", "settings": {{ "address": "127.0.0.1", "port": 5304 }} }}
        ]
    }}
    "#,
        custom = HEADER_CUSTOM_TCP,
    );

    let config2 = format!(
        r#"
    {{
        "log": {{ "level": "trace" }},
        "inbounds": [
            {{
                "protocol": "chain",
                "address": "127.0.0.1",
                "port": 5304,
                "settings": {{ "actors": ["finalmask", "socks"] }}
            }},
            {{
                "protocol": "finalmask",
                "tag": "finalmask",
                "settings": {{
                    "tcp": [
                        {{ "maskType": "header-custom", "settings": {custom:?} }}
                    ]
                }}
            }},
            {{ "protocol": "socks", "tag": "socks" }}
        ],
        "outbounds": [ {{ "protocol": "direct" }} ]
    }}
    "#,
        custom = HEADER_CUSTOM_TCP,
    );

    common::test_configs_tcp_only(vec![config1, config2], "127.0.0.1", 5303)
}
