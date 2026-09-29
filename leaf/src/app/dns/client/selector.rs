// Xray's server selection engine: `sortClients`, `makeGroups`, `serialQuery`
// and `parallelQuery`.
//
// Textually included into the `client` module by `include!("client/selector.rs")`.

/// An adjacent run of servers that may race against each other.
struct Group {
    start: usize,
    end: usize,
}

impl DnsClient {
    /// Orders the candidate servers for `domain` following Xray's `sortClients`.
    ///
    /// Domain rules win first (in server order), local servers additionally own
    /// the implicit local-TLD rules, a `finalQuery` server truncates the list,
    /// and the remaining servers are appended as the fallback list unless
    /// `disableFallback` / `disableFallbackIfMatch` suppressed it.
    fn sort_clients<'a>(&self, domain: &str, servers: &[&'a NsClient]) -> Vec<&'a NsClient> {
        let domain = domain.trim_end_matches('.').to_lowercase();
        let mut clients: Vec<&'a NsClient> = Vec::new();
        let mut used = vec![false; servers.len()];
        let mut has_match = false;

        for (idx, ns) in servers.iter().enumerate() {
            if matches!(ns.resolver, Resolver::System(_)) {
                for rule in local_domain_rules().iter() {
                    if rule.matches(&domain) {
                        used[idx] = true;
                        has_match = true;
                        clients.push(ns);
                        if ns.final_query {
                            return clients;
                        }
                        break;
                    }
                }
            }
            if used[idx] {
                continue;
            }
            for rule in &ns.domains {
                if rule.matches(&domain) {
                    used[idx] = true;
                    has_match = true;
                    clients.push(ns);
                    if ns.final_query {
                        return clients;
                    }
                    break;
                }
            }
        }

        if !(self.disable_fallback || (self.disable_fallback_if_match && has_match)) {
            for (idx, ns) in servers.iter().enumerate() {
                if used[idx] || ns.skip_fallback {
                    continue;
                }
                used[idx] = true;
                clients.push(ns);
                if ns.final_query {
                    return clients;
                }
            }
        }

        if clients.is_empty() {
            if let Some(first) = servers.first() {
                clients.push(first);
            }
        }

        clients
    }

    /// Merges only adjacent and rule-equivalent servers into a group, exactly
    /// like Xray's `makeGroups`.
    fn make_groups(clients: &[&NsClient]) -> (Vec<Group>, Vec<usize>) {
        let n = clients.len();
        let mut groups = Vec::with_capacity(n);
        let mut group_of = vec![0usize; n];
        if n == 0 {
            return (groups, group_of);
        }

        let mut s = 0usize;
        let mut e = 0usize;
        for i in 1..n {
            if clients[i - 1].policy_key == clients[i].policy_key {
                e = i;
            } else {
                for k in s..=e {
                    group_of[k] = groups.len();
                }
                groups.push(Group { start: s, end: e });
                s = i;
                e = i;
            }
        }
        for k in s..=e {
            group_of[k] = groups.len();
        }
        groups.push(Group { start: s, end: e });

        (groups, group_of)
    }

    /// Queries the ordered servers one by one and returns the first answer.
    async fn serial_query(
        &self,
        clients: &[&NsClient],
        host: &str,
        ty: RecordType,
        request: &[u8],
    ) -> Result<CacheEntry> {
        let mut errs = Vec::new();
        for client in clients {
            match self
                .query_task(client, request.to_vec(), host, ty)
                .await
            {
                Ok(entry) if !entry.ips.is_empty() => return Ok(entry),
                Ok(_) => {
                    errs.push(anyhow!("empty response from {}", client));
                }
                Err(e) => {
                    debug!(
                        "failed to lookup {} at server {} in serial query mode: {}",
                        host, client, e
                    );
                    errs.push(e);
                }
            }
        }
        Err(merge_query_errors(errs))
    }

    /// Race the servers group by group; the first group with a successful
    /// answer wins, exactly like Xray's `parallelQuery`.
    async fn parallel_query(
        &self,
        clients: &[&NsClient],
        host: &str,
        ty: RecordType,
        request: &[u8],
    ) -> Result<CacheEntry> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let (groups, group_of) = Self::make_groups(clients);
        let mut results: Vec<Option<Result<CacheEntry>>> = (0..clients.len()).map(|_| None).collect();
        let mut pending: Vec<usize> = groups.iter().map(|g| g.end - g.start + 1).collect();
        let mut errs = Vec::new();

        let mut tasks = FuturesUnordered::new();
        for (i, client) in clients.iter().enumerate() {
            let client = *client;
            let request = request.to_vec();
            let host = host.to_owned();
            tasks.push(async move {
                let res = self.query_task(client, request, &host, ty).await;
                (i, res)
            });
        }

        let mut next_group = 0usize;
        while let Some((i, res)) = tasks.next().await {
            let gi = group_of[i];
            pending[gi] = pending[gi].saturating_sub(1);
            results[i] = Some(res);

            while next_group < groups.len() {
                let g = &groups[next_group];

                for j in g.start..=g.end {
                    if let Some(Ok(entry)) = &results[j] {
                        if !entry.ips.is_empty() {
                            return Ok(entry.clone());
                        }
                    }
                }

                if pending[next_group] > 0 {
                    break;
                }

                for j in g.start..=g.end {
                    match &results[j] {
                        Some(Err(e)) => errs.push(anyhow!("{}", e)),
                        Some(Ok(_)) => errs.push(anyhow!("empty response from {}", clients[j])),
                        None => (),
                    }
                }
                next_group += 1;
            }
        }

        Err(merge_query_errors(errs))
    }
}

fn merge_query_errors(errs: Vec<anyhow::Error>) -> anyhow::Error {
    if errs.is_empty() {
        return anyhow!("empty response");
    }
    let mut messages = Vec::with_capacity(errs.len());
    for err in errs {
        messages.push(err.to_string());
    }
    anyhow!("all dns queries failed: {}", messages.join("; "))
}
