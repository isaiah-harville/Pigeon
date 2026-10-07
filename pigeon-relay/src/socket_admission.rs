//! Ephemeral per-address admission. Addresses never enter durable state or logs.

use axum::http::HeaderMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_SOCKETS_PER_IP: usize = 32;
const MAX_INVITE_DEPOSITS_PER_IP_MINUTE: usize = 12;
const MAX_TRACKED_IPS: usize = 4096;

#[derive(Default)]
struct Entry {
    sockets: usize,
    invite_window: Option<(Instant, usize)>,
}

#[derive(Clone, Default)]
pub struct SocketAdmission(Arc<Mutex<HashMap<IpAddr, Entry>>>);

pub struct SocketPermit {
    admission: SocketAdmission,
    address: IpAddr,
}

impl SocketAdmission {
    pub fn acquire(&self, address: IpAddr) -> Option<SocketPermit> {
        let mut entries = self.0.lock().unwrap();
        prune(&mut entries);
        if !entries.contains_key(&address) && entries.len() >= MAX_TRACKED_IPS {
            return None;
        }
        let entry = entries.entry(address).or_default();
        if entry.sockets >= MAX_SOCKETS_PER_IP {
            return None;
        }
        entry.sockets += 1;
        Some(SocketPermit {
            admission: self.clone(),
            address,
        })
    }

    pub fn admit_invite(&self, address: IpAddr) -> bool {
        let mut entries = self.0.lock().unwrap();
        prune(&mut entries);
        if !entries.contains_key(&address) && entries.len() >= MAX_TRACKED_IPS {
            return false;
        }
        let entry = entries.entry(address).or_default();
        let now = Instant::now();
        let (start, count) = entry.invite_window.get_or_insert((now, 0));
        if now.duration_since(*start) >= Duration::from_secs(60) {
            *start = now;
            *count = 0;
        }
        if *count >= MAX_INVITE_DEPOSITS_PER_IP_MINUTE {
            return false;
        }
        *count += 1;
        true
    }
}

pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxy: Option<IpAddr>) -> IpAddr {
    if trusted_proxy != Some(peer) {
        return peer;
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

fn prune(entries: &mut HashMap<IpAddr, Entry>) {
    let now = Instant::now();
    entries.retain(|_, entry| {
        entry.sockets > 0
            || entry
                .invite_window
                .is_some_and(|(start, _)| now.duration_since(start) < Duration::from_secs(60))
    });
}

impl Drop for SocketPermit {
    fn drop(&mut self) {
        let mut entries = self.admission.0.lock().unwrap();
        if let Some(entry) = entries.get_mut(&self.address) {
            entry.sockets -= 1;
            if entry.sockets == 0 && entry.invite_window.is_none() {
                entries.remove(&self.address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_limit_is_per_ip_and_released_on_drop() {
        let admission = SocketAdmission::default();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        let permits: Vec<_> = (0..MAX_SOCKETS_PER_IP)
            .map(|_| admission.acquire(first).unwrap())
            .collect();
        assert!(admission.acquire(first).is_none());
        assert!(admission.acquire(second).is_some());
        drop(permits);
        assert!(admission.acquire(first).is_some());
    }

    #[test]
    fn invite_rate_is_per_ip() {
        let admission = SocketAdmission::default();
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..MAX_INVITE_DEPOSITS_PER_IP_MINUTE {
            assert!(admission.admit_invite(first));
        }
        assert!(!admission.admit_invite(first));
        assert!(admission.admit_invite(second));
    }

    #[test]
    fn forwarded_address_requires_matching_trusted_proxy() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let claimed: IpAddr = "192.0.2.9".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "192.0.2.9".parse().unwrap());
        assert_eq!(client_ip(peer, &headers, None), peer);
        assert_eq!(client_ip(peer, &headers, Some(peer)), claimed);
    }
}
