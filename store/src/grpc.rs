use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use futures::{SinkExt, StreamExt};
use hashbrown::HashSet;
use serde::Deserialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use yellowstone_grpc_client::{
    ClientTlsConfig, GeyserGrpcClient, GeyserStream, SubscribeRequestSink,
};
use yellowstone_grpc_proto::geyser::{
    subscribe_update::UpdateOneof, CommitmentLevel, SubscribeRequest,
    SubscribeRequestFilterAccounts, SubscribeUpdateAccount,
};
use yellowstone_shield_parser::accounts::{parse_account, ShieldProgramState, ID as PROGRAM_ID};

use crate::{PolicyCache, PolicyRpcClient, PolicyStore, Snapshot, StoreError, StoreResult};

#[derive(Deserialize, Clone)]
pub struct PolicyStoreRpcConfig {
    pub endpoint: String,

    /// How often all policies are re-fetched over RPC. Closed policies are not always visible
    /// on the gRPC stream, so this is the fallback that removes them from the cache.
    #[serde(with = "humantime_serde", default = "default_resync_interval")]
    pub resync_interval: Duration,
}

fn default_resync_interval() -> Duration {
    Duration::from_secs(300)
}

#[derive(Deserialize, Clone)]
pub struct PolicyStoreGrpcConfig {
    pub endpoint: String,

    #[serde(default = "default_commitment")]
    pub commitment: Option<ShieldStoreCommitmentLevel>,

    pub x_token: Option<String>,

    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,

    #[serde(with = "humantime_serde", default = "default_connect_timeout")]
    pub connect_timeout: Duration,

    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,

    #[serde(default = "default_http2_adaptive_window")]
    pub http2_adaptive_window: bool,

    #[serde(default = "default_http2_keep_alive")]
    pub http2_keep_alive: bool,

    #[serde(with = "humantime_serde")]
    pub http2_keep_alive_interval: Option<Duration>,

    #[serde(with = "humantime_serde")]
    pub http2_keep_alive_timeout: Option<Duration>,

    pub http2_keep_alive_while_idle: Option<bool>,

    #[serde(default = "default_max_decoding_message_size")]
    pub max_decoding_message_size: Option<usize>,

    pub initial_connection_window_size: Option<u32>,

    pub initial_stream_window_size: Option<u32>,
}

fn default_commitment() -> Option<ShieldStoreCommitmentLevel> {
    Some(ShieldStoreCommitmentLevel::Confirmed)
}

fn default_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_tcp_nodelay() -> bool {
    true
}

fn default_max_decoding_message_size() -> Option<usize> {
    Some(2u32.pow(24) as usize) // 16 MiB (Should be enough for receiving accounts)
}

fn default_http2_adaptive_window() -> bool {
    true
}

fn default_http2_keep_alive() -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldStoreCommitmentLevel {
    Processed,
    Confirmed,
    Finalized,
}

impl From<ShieldStoreCommitmentLevel> for CommitmentLevel {
    fn from(def: ShieldStoreCommitmentLevel) -> Self {
        match def {
            ShieldStoreCommitmentLevel::Processed => CommitmentLevel::Processed,
            ShieldStoreCommitmentLevel::Confirmed => CommitmentLevel::Confirmed,
            ShieldStoreCommitmentLevel::Finalized => CommitmentLevel::Finalized,
        }
    }
}

impl<'de> Deserialize<'de> for ShieldStoreCommitmentLevel {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        match s {
            "processed" => Ok(ShieldStoreCommitmentLevel::Processed),
            "confirmed" => Ok(ShieldStoreCommitmentLevel::Confirmed),
            "finalized" => Ok(ShieldStoreCommitmentLevel::Finalized),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid commitment level: {}",
                s
            ))),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct PolicyStoreConfig {
    pub rpc: PolicyStoreRpcConfig,
    pub grpc: PolicyStoreGrpcConfig,
}

#[derive(Default)]
pub struct PolicyStoreBuilder {
    config: Option<PolicyStoreConfig>,
}

impl PolicyStoreBuilder {
    pub fn config(&mut self, config: PolicyStoreConfig) -> &mut Self {
        self.config = Some(config);

        self
    }

    pub async fn run(&mut self) -> StoreResult<PolicyStore> {
        let config = self.config.take().ok_or(StoreError::NoConfig)?;
        let rpc = PolicyRpcClient::new(RpcClient::new(config.rpc.endpoint.clone()));

        let policies = rpc
            .list(&PROGRAM_ID)
            .await
            .map_err(|e| StoreError::RpcError(e.to_string()))?;

        let cache: Arc<PolicyCache> = Arc::new(policies.into());
        let snapshot = Arc::new(ArcSwap::from_pointee(Snapshot::new(&cache)));

        // The first subscription fails fast, so a bad endpoint or token is reported to the caller.
        // Later disconnects are retried in the background.
        let subscribed = cache.addresses();
        let (sink, stream) = subscribe(&config.grpc, &subscribed).await?;

        log::info!("Subscribed to Shield program account updates");

        tokio::spawn(process_updates(
            config,
            rpc,
            cache,
            Arc::downgrade(&snapshot),
            Subscription {
                sink,
                stream,
                addresses: subscribed,
            },
        ));

        Ok(PolicyStore::new(snapshot))
    }
}

const MIN_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

struct Subscription {
    sink: SubscribeRequestSink,
    stream: GeyserStream,
    /// Policy addresses included in the current subscription request.
    addresses: HashSet<Pubkey>,
}

/// Connects to the gRPC endpoint and subscribes to the Shield program accounts and the given
/// policy addresses.
async fn subscribe(
    config: &PolicyStoreGrpcConfig,
    addresses: &HashSet<Pubkey>,
) -> StoreResult<(SubscribeRequestSink, GeyserStream)> {
    let mut builder = GeyserGrpcClient::build_from_shared(config.endpoint.clone())
        .map_err(|e| StoreError::GrpcClientError(format!("Failed to build gRPC client: {}", e)))?
        .connect_timeout(config.connect_timeout)
        .timeout(config.timeout);

    if config.tcp_nodelay {
        builder = builder.tcp_nodelay(true);
    }

    if config.http2_adaptive_window {
        builder = builder.http2_adaptive_window(true);
    }

    builder = builder
        .tls_config(ClientTlsConfig::new().with_native_roots())
        .map_err(|e| StoreError::GrpcClientError(format!("Failed to set TLS config: {}", e)))?;

    // HTTP/2 keep-alive settings
    if config.http2_keep_alive {
        if let Some(interval) = config.http2_keep_alive_interval {
            builder = builder.http2_keep_alive_interval(interval);
        }

        if let Some(timeout) = config.http2_keep_alive_timeout {
            builder = builder.keep_alive_timeout(timeout);
        }

        if let Some(while_idle) = config.http2_keep_alive_while_idle {
            builder = builder.keep_alive_while_idle(while_idle);
        }
    }

    if let Some(max_size) = config.max_decoding_message_size {
        builder = builder.max_decoding_message_size(max_size)
    }

    if let Some(window_size) = config.initial_connection_window_size {
        builder = builder.initial_connection_window_size(window_size);
    }

    if let Some(stream_window_size) = config.initial_stream_window_size {
        builder = builder.initial_stream_window_size(stream_window_size);
    }

    // Apply authentication token if provided
    let builder = if let Some(ref token) = config.x_token {
        builder
            .x_token(Some(token.clone()))
            .map_err(|e| StoreError::GrpcClientError(format!("Failed to set x-token: {}", e)))?
    } else {
        builder
    };

    let mut client = builder.connect().await.map_err(|e| {
        StoreError::GrpcConnectionError(format!("Failed to connect to gRPC server: {}", e))
    })?;

    log::info!("Connected to gRPC endpoint: {}", config.endpoint);

    client
        .subscribe_with_request(Some(subscribe_request(addresses)))
        .await
        .map_err(|e| {
            StoreError::GrpcSubscriptionError(format!("Failed to subscribe to gRPC stream: {}", e))
        })
}

/// Rebuilds the snapshot from the cache.
///
/// # Returns
///
/// `false` if the [`PolicyStore`] was dropped and there is nobody left to update.
fn publish(cache: &PolicyCache, snapshot: &Weak<ArcSwap<Snapshot>>) -> bool {
    match snapshot.upgrade() {
        Some(snapshot) => {
            snapshot.store(Arc::new(Snapshot::new(cache)));
            true
        }
        None => false,
    }
}

/// Re-fetches all policies over RPC.
///
/// # Returns
///
/// `true` if the cache was updated.
async fn resync(rpc: &PolicyRpcClient, cache: &PolicyCache) -> bool {
    match rpc.list(&PROGRAM_ID).await {
        Ok(policies) => {
            cache.sync(policies);
            true
        }
        Err(e) => {
            log::warn!("Failed to resync policies over RPC: {}", e);
            false
        }
    }
}

/// Applies gRPC updates and periodic RPC resyncs to the cache until the [`PolicyStore`] is
/// dropped. Reconnects with exponential backoff when the stream ends or fails.
async fn process_updates(
    config: PolicyStoreConfig,
    rpc: PolicyRpcClient,
    cache: Arc<PolicyCache>,
    snapshot: Weak<ArcSwap<Snapshot>>,
    subscription: Subscription,
) {
    let mut resync_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + config.rpc.resync_interval,
        config.rpc.resync_interval,
    );
    resync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut backoff = MIN_RECONNECT_BACKOFF;
    let mut connected = Some(subscription);

    loop {
        let mut subscription = match connected.take() {
            Some(subscription) => subscription,
            None => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);

                if snapshot.strong_count() == 0 {
                    return;
                }

                // Updates may have been missed while disconnected.
                if resync(&rpc, &cache).await && !publish(&cache, &snapshot) {
                    return;
                }

                let addresses = cache.addresses();
                match subscribe(&config.grpc, &addresses).await {
                    Ok((sink, stream)) => {
                        log::info!("Resubscribed to Shield program account updates");
                        backoff = MIN_RECONNECT_BACKOFF;
                        Subscription {
                            sink,
                            stream,
                            addresses,
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to resubscribe, retrying in {:?}: {}", backoff, e);
                        continue;
                    }
                }
            }
        };

        loop {
            let changed = tokio::select! {
                message = subscription.stream.next() => match message {
                    Some(Ok(msg)) => match msg.update_oneof {
                        Some(UpdateOneof::Account(account_update)) => {
                            apply_account_update(&cache, account_update)
                        }
                        _ => false,
                    },
                    Some(Err(e)) => {
                        log::error!("Error receiving gRPC message: {}", e);
                        break;
                    }
                    None => break,
                },
                _ = resync_interval.tick() => resync(&rpc, &cache).await,
            };

            if snapshot.strong_count() == 0 {
                return;
            }

            if !changed {
                continue;
            }

            if !publish(&cache, &snapshot) {
                return;
            }

            // Closing a policy assigns it to the system program, so the owner filter never
            // sees the close. Subscribing to the known addresses as well catches it.
            let addresses = cache.addresses();
            if addresses != subscription.addresses {
                if let Err(e) = subscription.sink.send(subscribe_request(&addresses)).await {
                    log::error!("Failed to update gRPC subscription: {}", e);
                    break;
                }
                subscription.addresses = addresses;
            }
        }

        log::warn!("gRPC stream ended, reconnecting in {:?}", backoff);
    }
}

const OWNER_FILTER: &str = "shield-policies-by-owner";
const ADDRESS_FILTER: &str = "shield-policies-by-address";

/// Builds the subscription for all Shield program accounts plus the given policy addresses.
fn subscribe_request(addresses: &HashSet<Pubkey>) -> SubscribeRequest {
    let mut accounts = std::collections::HashMap::new();
    accounts.insert(
        OWNER_FILTER.to_string(),
        SubscribeRequestFilterAccounts {
            owner: vec![PROGRAM_ID.to_string()],
            ..Default::default()
        },
    );

    // An account filter without addresses or owners matches every account, so only add it when
    // there is something to watch.
    if !addresses.is_empty() {
        accounts.insert(
            ADDRESS_FILTER.to_string(),
            SubscribeRequestFilterAccounts {
                account: addresses.iter().map(|a| a.to_string()).collect(),
                ..Default::default()
            },
        );
    }

    SubscribeRequest {
        accounts,
        ..Default::default()
    }
}

/// Applies a single account update to the cache.
///
/// An account that is no longer owned by the Shield program, has no lamports or no data was
/// closed and is removed from the cache.
///
/// # Returns
///
/// `true` if the cache changed.
fn apply_account_update(cache: &PolicyCache, account_update: SubscribeUpdateAccount) -> bool {
    let Some(account) = account_update.account else {
        return false;
    };

    let pubkey = match <[u8; 32]>::try_from(account.pubkey) {
        Ok(bytes) => Pubkey::from(bytes),
        Err(_) => {
            log::warn!("Invalid pubkey length in account update");
            return false;
        }
    };

    let owner = match <[u8; 32]>::try_from(account.owner) {
        Ok(bytes) => Pubkey::from(bytes),
        Err(_) => {
            log::warn!("Invalid owner length in account update");
            return false;
        }
    };

    if owner != PROGRAM_ID || account.lamports == 0 || account.data.is_empty() {
        let removed = cache.remove_at(&pubkey, account_update.slot);
        if removed {
            log::debug!("Removed closed policy: {}", pubkey);
        }
        return removed;
    }

    match parse_account(
        account_update.slot,
        pubkey,
        &owner,
        &account.data,
        Some(&PROGRAM_ID),
    ) {
        Ok(ShieldProgramState::Policy(slot, pubkey, policy)) => {
            cache.insert(pubkey, slot, policy);
            log::debug!("Updated policy for pubkey: {}", pubkey);
            true
        }
        Err(e) => {
            log::warn!("Failed to parse account update: {}", e);
            false
        }
    }
}

impl PolicyStore {
    pub fn build() -> PolicyStoreBuilder {
        PolicyStoreBuilder::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yellowstone_grpc_proto::{geyser::SubscribeUpdate, tonic};
    use yellowstone_shield_parser::accounts::{PermissionStrategy, Policy};

    use crate::CheckError;

    fn policy_v2_data(strategy: PermissionStrategy, identities: &[Pubkey]) -> Vec<u8> {
        let mut data = vec![1u8, strategy as u8, 255];
        data.extend_from_slice(Pubkey::new_unique().as_ref());
        data.extend_from_slice(&(identities.len() as u32).to_le_bytes());
        for identity in identities {
            data.extend_from_slice(identity.as_ref());
        }
        data
    }

    fn account_update(
        pubkey: Pubkey,
        owner: Pubkey,
        slot: u64,
        lamports: u64,
        data: Vec<u8>,
    ) -> SubscribeUpdateAccount {
        SubscribeUpdateAccount {
            account: Some(yellowstone_grpc_proto::geyser::SubscribeUpdateAccountInfo {
                pubkey: pubkey.to_bytes().to_vec(),
                owner: owner.to_bytes().to_vec(),
                lamports,
                data,
                ..Default::default()
            }),
            slot,
            ..Default::default()
        }
    }

    #[test]
    fn test_apply_account_update_inserts_policy() {
        let cache = PolicyCache::new();
        let address = Pubkey::new_unique();
        let validator = Pubkey::new_unique();

        let update = account_update(
            address,
            PROGRAM_ID,
            1,
            1_000_000,
            policy_v2_data(PermissionStrategy::Deny, &[validator]),
        );

        assert!(apply_account_update(&cache, update));

        let snapshot = Snapshot::new(&cache);
        assert_eq!(snapshot.is_allowed(&[address], &validator), Ok(false));
    }

    #[test]
    fn test_apply_account_update_removes_closed_policy() {
        let system_program = Pubkey::default();
        let validator = Pubkey::new_unique();

        let closed_updates = [
            // What the program does on close: no lamports, no data, owned by the system program.
            (system_program, 0, vec![]),
            (
                system_program,
                1_000_000,
                policy_v2_data(PermissionStrategy::Deny, &[validator]),
            ),
            (PROGRAM_ID, 0, vec![]),
            (PROGRAM_ID, 1_000_000, vec![]),
        ];

        for (owner, lamports, data) in closed_updates {
            let cache = PolicyCache::new();
            let address = Pubkey::new_unique();
            cache.insert(
                address,
                1,
                Policy::new(PermissionStrategy::Deny, vec![validator]),
            );

            let update = account_update(address, owner, 2, lamports, data);

            assert!(apply_account_update(&cache, update));
            assert!(cache.get(&address).is_none());
            assert_eq!(
                Snapshot::new(&cache).is_allowed(&[address], &validator),
                Err(CheckError::PolicyNotFound)
            );
        }
    }

    #[test]
    fn test_apply_account_update_ignores_stale_close() {
        let cache = PolicyCache::new();
        let address = Pubkey::new_unique();
        cache.insert(
            address,
            5,
            Policy::new(PermissionStrategy::Deny, vec![Pubkey::new_unique()]),
        );

        let update = account_update(address, Pubkey::default(), 4, 0, vec![]);

        assert!(!apply_account_update(&cache, update));
        assert!(cache.get(&address).is_some());
    }

    #[test]
    fn test_subscribe_request_filters() {
        let request = subscribe_request(&HashSet::new());
        assert_eq!(request.accounts.len(), 1);
        assert_eq!(
            request.accounts[OWNER_FILTER].owner,
            vec![PROGRAM_ID.to_string()]
        );

        let address = Pubkey::new_unique();
        let request = subscribe_request(&HashSet::from([address]));
        assert_eq!(request.accounts.len(), 2);
        assert_eq!(
            request.accounts[ADDRESS_FILTER].account,
            vec![address.to_string()]
        );
        assert!(request.accounts[ADDRESS_FILTER].owner.is_empty());
    }

    fn test_config() -> PolicyStoreConfig {
        toml::from_str(
            r#"
            [rpc]
            endpoint = "http://127.0.0.1:1"
            resync_interval = "1h"

            [grpc]
            endpoint = "http://127.0.0.1:1"
            http2_keep_alive_interval = "30s"
            http2_keep_alive_timeout = "10s"
            "#,
        )
        .unwrap()
    }

    struct MockConnection {
        updates: tokio::sync::mpsc::Sender<Result<SubscribeUpdate, tonic::Status>>,
        requests: futures::channel::mpsc::Receiver<SubscribeRequest>,
        subscription: Subscription,
    }

    fn mock_connection() -> MockConnection {
        let (updates, updates_rx) = tokio::sync::mpsc::channel(16);
        let (requests_tx, requests) = futures::channel::mpsc::channel(16);

        MockConnection {
            updates,
            requests,
            subscription: Subscription {
                sink: SubscribeRequestSink::mock(requests_tx),
                stream: GeyserStream::mock(updates_rx),
                addresses: HashSet::new(),
            },
        }
    }

    fn rpc_mock() -> PolicyRpcClient {
        PolicyRpcClient::new(RpcClient::new_mock("succeeds".to_string()))
    }

    fn account_message(update: SubscribeUpdateAccount) -> Result<SubscribeUpdate, tonic::Status> {
        Ok(SubscribeUpdate {
            update_oneof: Some(UpdateOneof::Account(update)),
            ..Default::default()
        })
    }

    fn ping_message() -> Result<SubscribeUpdate, tonic::Status> {
        Ok(SubscribeUpdate {
            update_oneof: Some(UpdateOneof::Ping(Default::default())),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_process_updates_applies_updates_and_extends_subscription() {
        let cache = Arc::new(PolicyCache::new());
        let snapshot = Arc::new(ArcSwap::from_pointee(Snapshot::new(&cache)));
        let MockConnection {
            updates,
            mut requests,
            subscription,
        } = mock_connection();

        let task = tokio::spawn(process_updates(
            test_config(),
            rpc_mock(),
            Arc::clone(&cache),
            Arc::downgrade(&snapshot),
            subscription,
        ));

        let address = Pubkey::new_unique();
        let validator = Pubkey::new_unique();
        updates
            .send(account_message(account_update(
                address,
                PROGRAM_ID,
                1,
                1_000_000,
                policy_v2_data(PermissionStrategy::Deny, &[validator]),
            )))
            .await
            .unwrap();

        let request = requests.next().await.unwrap();
        assert_eq!(
            request.accounts[ADDRESS_FILTER].account,
            vec![address.to_string()]
        );
        assert_eq!(
            snapshot.load().is_allowed(&[address], &validator),
            Ok(false)
        );

        // The task stops once the store is dropped.
        drop(snapshot);
        updates.send(ping_message()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_process_updates_keeps_running_after_stream_ends() {
        let cache = Arc::new(PolicyCache::new());
        let snapshot = Arc::new(ArcSwap::from_pointee(Snapshot::new(&cache)));
        let MockConnection {
            updates,
            requests: _requests,
            subscription,
        } = mock_connection();

        let task = tokio::spawn(process_updates(
            test_config(),
            rpc_mock(),
            Arc::clone(&cache),
            Arc::downgrade(&snapshot),
            subscription,
        ));

        // End the stream. Reconnecting fails because nothing listens on the endpoint, but the
        // task keeps retrying instead of giving up.
        drop(updates);
        tokio::time::sleep(MAX_RECONNECT_BACKOFF * 4).await;
        assert!(!task.is_finished());

        drop(snapshot);
        tokio::time::timeout(MAX_RECONNECT_BACKOFF * 2, task)
            .await
            .unwrap()
            .unwrap();
    }
}
