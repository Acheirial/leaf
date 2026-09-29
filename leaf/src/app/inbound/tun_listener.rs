use std::sync::Arc;

use anyhow::Result;

use crate::app::dispatcher::Dispatcher;
use crate::app::fake_dns::FakeDns;
use crate::app::nat_manager::NatManager;
use crate::config::Inbound;
use crate::proxy::tun;
use crate::Runner;

pub struct TunInboundListener {
    pub inbound: Inbound,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
    /// The process-wide fake-DNS engine shared with the dns client's
    /// `fakedns` server form.
    pub fake_dns: Arc<FakeDns>,
}

impl TunInboundListener {
    pub fn listen(&self) -> Result<Runner> {
        tun::inbound::new(
            self.inbound.clone(),
            self.dispatcher.clone(),
            self.nat_manager.clone(),
            self.fake_dns.clone(),
        )
    }
}
