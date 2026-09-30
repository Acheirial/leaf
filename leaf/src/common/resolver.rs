use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use futures::TryFutureExt;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::app::SyncDnsClient;
use crate::proxy::DialOrder;

pub struct Resolver {
    addrs: Vec<SocketAddr>,
}

impl Resolver {
    pub async fn new<'a>(
        dns_client: SyncDnsClient,
        address: &'a String,
        port: &'a u16,
    ) -> Result<Self> {
        // A handler with no endpoint has nothing to dial. Looking the empty
        // name up instead asks the name servers for the root zone and then
        // dials port 0 of whatever answers -- and a dial that reaches the
        // dispatcher turns into another dial of the same handler, which is
        // how a chain's payload actor, configured without an endpoint on
        // purpose because it rides the transport the chain hands it, used to
        // recurse until the stack ran out.
        if address.is_empty() {
            return Err(anyhow!("no address to dial"));
        }

        let mut ips = {
            dns_client
                .read()
                .await
                .direct_lookup(address)
                .map_err(|e| anyhow!("lookup {} failed: {}", address, e))
                .await?
        };
        match *crate::option::OUTBOUND_DIAL_ORDER {
            DialOrder::Ordered => ips.reverse(),
            DialOrder::Random => ips.shuffle(&mut StdRng::from_entropy()),
            DialOrder::PartialRandom => {
                let head = ips.remove(0);
                ips.shuffle(&mut StdRng::from_entropy());
                ips.push(head);
            }
        }
        Ok(Resolver {
            addrs: ips.into_iter().map(|x| SocketAddr::new(x, *port)).collect(),
        })
    }
}

impl Iterator for Resolver {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.addrs.pop()
    }
}
