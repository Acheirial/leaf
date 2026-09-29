use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use protobuf::Message;

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::config;
use crate::proxy;
use crate::proxy::AnyInboundHandler;
use crate::Runner;

#[cfg(feature = "inbound-amux")]
use crate::proxy::amux;
#[cfg(feature = "inbound-finalmask")]
use crate::proxy::finalmask;
#[cfg(feature = "inbound-hc")]
use crate::proxy::hc;
#[cfg(feature = "inbound-http")]
use crate::proxy::http;
#[cfg(feature = "inbound-hysteria2")]
use crate::proxy::hysteria2;
#[cfg(feature = "inbound-mptp")]
use crate::proxy::mptp;
#[cfg(feature = "inbound-quic")]
use crate::proxy::quic;
#[cfg(feature = "inbound-reality")]
use crate::proxy::reality;
#[cfg(feature = "inbound-socks")]
use crate::proxy::socks;
#[cfg(feature = "inbound-tls")]
use crate::proxy::tls;
#[cfg(feature = "inbound-tproxy")]
use crate::proxy::tproxy;
#[cfg(feature = "inbound-vless")]
use crate::proxy::vless;
#[cfg(feature = "inbound-ws")]
use crate::proxy::ws;
#[cfg(feature = "inbound-xhttp")]
use crate::proxy::xhttp;

#[cfg(feature = "inbound-chain")]
use crate::proxy::chain;

use super::network_listener::NetworkInboundListener;

#[cfg(feature = "inbound-cat")]
use super::cat_listener::CatInboundListener;

#[cfg(feature = "inbound-tun")]
use super::tun_listener::TunInboundListener;

#[cfg(feature = "inbound-tproxy")]
use super::tproxy_listener::TproxyInboundListener;

pub struct InboundManager {
    network_listeners: HashMap<String, NetworkInboundListener>,
    #[cfg(feature = "inbound-tun")]
    tun_listener: Option<TunInboundListener>,
    #[cfg(feature = "inbound-cat")]
    cat_listener: Option<CatInboundListener>,
    #[cfg(feature = "inbound-tproxy")]
    tproxy_listener: Option<TproxyInboundListener>,
    tun_auto: bool,
}

impl InboundManager {
    pub fn new(
        inbounds: &[config::Inbound],
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, AnyInboundHandler> = HashMap::new();

        for inbound in inbounds.iter() {
            let tag = String::from(&inbound.tag);
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-socks")]
                "socks" => {
                    let mut username = None;
                    let mut password = None;
                    if !inbound.settings.is_empty() {
                        let settings =
                            config::SocksInboundSettings::parse_from_bytes(&inbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] inbound settings: {}", &tag, e)
                                })?;
                        username = if settings.username.is_empty() {
                            None
                        } else {
                            Some(settings.username)
                        };
                        password = if settings.password.is_empty() {
                            None
                        } else {
                            Some(settings.password)
                        };
                    }
                    let stream = Arc::new(socks::inbound::StreamHandler { username, password });
                    let datagram = Arc::new(socks::inbound::DatagramHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-http")]
                "http" => {
                    let stream = Arc::new(http::inbound::StreamHandler);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-mptp")]
                "mptp" => {
                    let stream = Arc::new(mptp::inbound::stream::Handler::new());
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-hc")]
                "hc" => {
                    let settings =
                        config::HcInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(hc::inbound::Handler::new(
                        settings.path,
                        settings.request,
                        settings.response,
                    ));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-ws")]
                "ws" => {
                    let settings =
                        config::WebSocketInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(ws::inbound::StreamHandler::new(settings.path.clone()));
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-quic")]
                "quic" => {
                    let settings = config::QuicInboundSettings::parse_from_bytes(&inbound.settings)
                        .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let datagram = Arc::new(quic::inbound::DatagramHandler::new(
                        settings.certificate.clone(),
                        settings.certificate_key.clone(),
                        settings.alpn.clone(),
                    )?);
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        None,
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-tls")]
                "tls" => {
                    let settings = config::TlsInboundSettings::parse_from_bytes(&inbound.settings)
                        .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(
                        tls::inbound::StreamHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound tls capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-vless")]
                "vless" => {
                    let settings = config::VlessInboundSettings::parse_from_bytes(&inbound.settings)
                        .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(
                        vless::inbound::StreamHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound vless capability: {}", &tag, e)
                        })?,
                    );
                    let datagram = Arc::new(
                        vless::inbound::DatagramHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound vless capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-reality")]
                "reality" => {
                    let settings =
                        config::RealityInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(
                        reality::inbound::StreamHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound reality capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        None,
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-xhttp")]
                "xhttp" => {
                    let settings = config::XhttpInboundSettings::parse_from_bytes(&inbound.settings)
                        .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(
                        xhttp::inbound::StreamHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound xhttp capability: {}", &tag, e)
                        })?,
                    );
                    let datagram = Arc::new(
                        xhttp::inbound::DatagramHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound xhttp capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-finalmask")]
                "finalmask" => {
                    let settings =
                        config::FinalmaskInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let stream = Arc::new(
                        finalmask::inbound::StreamHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound finalmask capability: {}", &tag, e)
                        })?,
                    );
                    let datagram = Arc::new(
                        finalmask::inbound::DatagramHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound finalmask capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        Some(stream),
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                #[cfg(feature = "inbound-hysteria2")]
                "hysteria2" => {
                    let settings =
                        config::Hysteria2InboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let datagram = Arc::new(
                        hysteria2::inbound::DatagramHandler::new(&settings).map_err(|e| {
                            anyhow!("invalid [{}] inbound hysteria2 capability: {}", &tag, e)
                        })?,
                    );
                    let handler = Arc::new(proxy::inbound::Handler::new(
                        tag.clone(),
                        None,
                        Some(datagram),
                    ));
                    handlers.insert(tag.clone(), handler);
                }
                _ => (),
            }
        }

        for _i in 0..4 {
            for inbound in inbounds.iter() {
                let tag = String::from(&inbound.tag);
                #[allow(clippy::single_match)]
                match inbound.protocol.as_str() {
                    #[cfg(feature = "inbound-amux")]
                    "amux" => {
                        let mut actors = Vec::new();
                        let settings =
                            config::AMuxInboundSettings::parse_from_bytes(&inbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] inbound settings: {}", &tag, e)
                                })?;
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        let stream = Arc::new(amux::inbound::StreamHandler {
                            actors: actors.clone(),
                        });
                        let handler = Arc::new(proxy::inbound::Handler::new(
                            tag.clone(),
                            Some(stream),
                            None,
                        ));
                        handlers.insert(tag.clone(), handler);
                    }
                    #[cfg(feature = "inbound-chain")]
                    "chain" => {
                        let settings =
                            config::ChainInboundSettings::parse_from_bytes(&inbound.settings)
                                .map_err(|e| {
                                    anyhow!("invalid [{}] inbound settings: {}", &tag, e)
                                })?;
                        let mut actors = Vec::new();
                        for actor in settings.actors.iter() {
                            if let Some(a) = handlers.get(actor) {
                                actors.push(a.clone());
                            }
                        }
                        if actors.is_empty() {
                            continue;
                        }
                        let stream = if actors[0].stream().is_ok() {
                            let h = Arc::new(chain::inbound::StreamHandler {
                                actors: actors.clone(),
                            });
                            Some(h as crate::proxy::AnyInboundStreamHandler)
                        } else {
                            None
                        };
                        let datagram = if actors[0].datagram().is_ok() {
                            let h = Arc::new(chain::inbound::DatagramHandler { actors });
                            Some(h as crate::proxy::AnyInboundDatagramHandler)
                        } else {
                            None
                        };
                        let handler =
                            Arc::new(proxy::inbound::Handler::new(tag.clone(), stream, datagram));
                        handlers.insert(tag.clone(), handler);
                    }
                    _ => (),
                }
            }
        }

        let mut network_listeners: HashMap<String, NetworkInboundListener> = HashMap::new();

        #[cfg(feature = "inbound-tun")]
        let mut tun_listener: Option<TunInboundListener> = None;

        #[cfg(feature = "inbound-cat")]
        let mut cat_listener: Option<CatInboundListener> = None;

        #[cfg(feature = "inbound-tproxy")]
        let mut tproxy_listener: Option<TproxyInboundListener> = None;

        let mut tun_auto = false;

        for inbound in inbounds.iter() {
            let tag = String::from(&inbound.tag);
            match inbound.protocol.as_str() {
                #[cfg(feature = "inbound-tun")]
                "tun" => {
                    let listener = TunInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    tun_listener.replace(listener);
                    let settings =
                        crate::config::TunInboundSettings::parse_from_bytes(&inbound.settings)?;
                    tun_auto = settings.auto;
                }
                #[cfg(feature = "inbound-cat")]
                "cat" => {
                    let listener = CatInboundListener {
                        inbound: inbound.clone(),
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                    };
                    cat_listener.replace(listener);
                }
                #[cfg(feature = "inbound-tproxy")]
                "tproxy" => {
                    let settings =
                        config::TproxyInboundSettings::parse_from_bytes(&inbound.settings)
                            .map_err(|e| anyhow!("invalid [{}] inbound settings: {}", &tag, e))?;
                    let listen_addr =
                        std::net::SocketAddr::new(inbound.address.parse()?, inbound.port as u16);
                    let handler: AnyInboundHandler =
                        Arc::new(tproxy::inbound::Handler::new(&settings, &tag));
                    let listener = TproxyInboundListener {
                        handler,
                        dispatcher: dispatcher.clone(),
                        nat_manager: nat_manager.clone(),
                        tcp_addr: listen_addr,
                        udp_addr: listen_addr,
                    };
                    tproxy_listener.replace(listener);
                }
                _ => {
                    if let Some(h) = handlers.get(&tag) {
                        let listener = NetworkInboundListener {
                            address: inbound.address.clone(),
                            port: inbound.port as u16,
                            handler: h.clone(),
                            dispatcher: dispatcher.clone(),
                            nat_manager: nat_manager.clone(),
                        };
                        network_listeners.insert(tag.clone(), listener);
                    }
                }
            }
        }

        Ok(InboundManager {
            network_listeners,
            #[cfg(feature = "inbound-tun")]
            tun_listener,
            #[cfg(feature = "inbound-cat")]
            cat_listener,
            #[cfg(feature = "inbound-tproxy")]
            tproxy_listener,
            tun_auto,
        })
    }

    pub fn get_network_runners(&self) -> Result<Vec<Runner>> {
        let mut runners: Vec<Runner> = Vec::new();
        for (_, listener) in self.network_listeners.iter() {
            runners.append(&mut listener.listen()?);
        }
        Ok(runners)
    }

    #[cfg(feature = "inbound-tun")]
    pub fn get_tun_runner(&self) -> Option<Result<Runner>> {
        self.tun_listener.as_ref().map(TunInboundListener::listen)
    }

    #[cfg(feature = "inbound-cat")]
    pub fn get_cat_runner(&self) -> Option<Result<Runner>> {
        self.cat_listener.as_ref().map(CatInboundListener::listen)
    }

    #[cfg(feature = "inbound-tproxy")]
    pub fn get_tproxy_runners(&self) -> Result<Vec<Runner>> {
        match self.tproxy_listener.as_ref() {
            Some(listener) => listener.listen(),
            None => Ok(Vec::new()),
        }
    }

    #[cfg(feature = "inbound-tun")]
    pub fn has_tun_listener(&self) -> bool {
        self.tun_listener.is_some()
    }

    pub fn tun_auto(&self) -> bool {
        self.tun_auto
    }
}
