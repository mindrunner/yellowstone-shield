use std::sync::{Arc, Weak};

use anyhow::Result;
use arc_swap::ArcSwap;
use futures::{SinkExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::Deserialize;

use solana_account::Account;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
};
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use std::time::Duration;
use yellowstone_grpc_client::{
    ClientTlsConfig, GeyserGrpcClient, GeyserStream, SubscribeRequestSink,
};
use yellowstone_grpc_proto::geyser::{
    subscribe_update::UpdateOneof, CommitmentLevel, SubscribeRequest,
    SubscribeRequestFilterAccounts, SubscribeUpdateAccount,
};
use yellowstone_shield_parser::accounts::{
    parse_account, PermissionStrategy, Policy, ShieldProgramState, ID as PROGRAM_ID,
};

pub struct SlotCacheItem<T> {
    slot: u64,
    item: T,
}

/// A thread-safe cache for storing policies by their associated public keys.
pub struct PolicyCache {
    /// A read-write lock-protected hash map that stores policies keyed by public keys.
    /// Each entry contains a tuple of the slot number and the policy.
    policies: RwLock<HashMap<Pubkey, SlotCacheItem<Policy>>>,
}

impl Default for PolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyCache {
    /// Creates a new, empty PolicyCache.
    ///
    /// # Returns
    ///
    /// A new instance of `PolicyCache` with an empty internal storage.
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
        }
    }

    /// Inserts a policy into the cache, associating it with the given public key.
    /// Only updates if the incoming slot is greater than the current slot.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The public key to associate with the policy.
    /// * `slot` - The slot number of the policy update.
    /// * `policy` - The policy to be stored in the cache.
    pub fn insert(&self, pubkey: Pubkey, slot: u64, item: Policy) {
        let mut policies = self.policies.write();
        if let Some(current_item) = policies.get(&pubkey) {
            if slot > current_item.slot {
                policies.insert(pubkey, SlotCacheItem { slot, item });
            }
        } else {
            policies.insert(pubkey, SlotCacheItem { slot, item });
        }
    }

    /// Retrieves a policy from the cache associated with the given public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The public key whose associated policy is to be retrieved.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the policy if found, or `None` if no policy is associated
    /// with the given public key.
    pub fn get(&self, pubkey: &Pubkey) -> Option<Policy> {
        self.policies
            .read()
            .get(pubkey)
            .map(|item| item.item.clone())
    }

    /// Removes a policy from the cache associated with the given public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - The public key whose associated policy is to be removed.
    ///
    /// # Returns
    ///
    /// `Some(())` if a policy was removed, or `None` if no policy was associated with the given public key.
    pub fn remove(&self, pubkey: &Pubkey) -> Option<()> {
        self.policies.write().remove(pubkey).map(|_| ())
    }

    /// Removes a policy that was closed at the given slot.
    /// Only removes if the slot is not older than the cached policy.
    ///
    /// # Returns
    ///
    /// `true` if a policy was removed.
    pub fn remove_at(&self, pubkey: &Pubkey, slot: u64) -> bool {
        let mut policies = self.policies.write();
        match policies.get(pubkey) {
            Some(current_item) if slot >= current_item.slot => {
                policies.remove(pubkey);
                true
            }
            _ => false,
        }
    }

    /// Synchronizes the cache with a full listing of the program accounts.
    ///
    /// Policies from the response are inserted with the usual slot check. Cached policies that
    /// are missing from the response were closed and get removed, unless they were updated
    /// after the response slot.
    pub fn sync(&self, response: PoliciesSlotRpcResponse) {
        let listed: HashSet<Pubkey> = response.result.iter().map(|(k, _)| *k).collect();

        self.policies
            .write()
            .retain(|k, item| listed.contains(k) || item.slot > response.slot);

        for (address, policy) in response.result.into_iter() {
            self.insert(address, response.slot, policy);
        }
    }

    /// Retrieves the addresses of all policies currently stored in the cache.
    pub fn addresses(&self) -> HashSet<Pubkey> {
        self.policies.read().keys().copied().collect()
    }

    /// Retrieves all policies currently stored in the cache.
    ///
    /// # Returns
    ///
    /// A vector of tuples where each tuple contains a reference to a public key and its
    /// associated policy.
    pub fn all(&self) -> Vec<(Pubkey, Policy)> {
        self.policies
            .read()
            .iter()
            .map(|(k, item)| (*k, item.item.clone()))
            .collect()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckError {
    #[error("Policy not found")]
    PolicyNotFound,
}

/// permission strategies for specific identities.
///
/// The `Snapshot` struct is designed to facilitate quick lookups of permission strategies
/// associated with a combination of policy and identity public keys. It is particularly
/// useful for determining whether a specific identity is allowed or denied by a set of
/// policies.
#[derive(Default)]
pub struct Snapshot {
    /// A hash set that stores tuples of policy and identity public keys for quick lookup.
    lookup: HashSet<(Pubkey, Pubkey)>,
    strategies: HashMap<Pubkey, PermissionStrategy>,
}

impl Snapshot {
    /// Creates a new `Snapshot` from a `PolicyCache`.
    ///
    /// # Arguments
    ///
    /// * `cache` - A reference to a `PolicyCache` from which to create the snapshot.
    ///
    /// # Returns
    ///
    /// A new instance of `Snapshot` with a populated lookup table for quick access to
    /// permission strategies.
    pub fn new(cache: &PolicyCache) -> Self {
        let mut lookup = HashSet::new();
        let mut strategies = HashMap::new();

        for (address, policy) in cache.all().iter() {
            strategies.insert(*address, policy.strategy);
            for identity in &policy.identities {
                lookup.insert((*address, *identity));
            }
        }

        Self { lookup, strategies }
    }

    /// Determines if a identity is allowed by any of the specified policy pubkey.
    ///
    /// This function iterates over a list of policy public keys and checks if a given validator
    /// is allowed according to the permission strategies associated with those policies.
    ///
    /// The function maintains a boolean flag `not_found` initialized to `true`. This flag is used
    /// to track whether any policy with an `Allow` strategy has been encountered that does not
    /// explicitly deny the identity.
    ///
    /// For each policy public key in the provided slice:
    /// - It retrieves the associated permission strategy from the `strategies` map.
    /// - It checks if the combination of the policy public key and the identity public key exists
    ///   in the `lookup` set.
    ///   - If the combination exists, it evaluates the permission strategy:
    ///     - If the strategy is `Deny`, the function immediately returns `false`, indicating the
    ///       identity is not allowed.
    ///     - If the strategy is `Allow`, the function immediately returns `true`, indicating the
    ///       identity is allowed.
    ///   - If the combination does not exist and the strategy is `Allow`, it sets `not_found` to `false`,
    ///     indicating that there is at least one policy that could potentially allow the validator.
    ///
    /// After iterating through all policies, if no explicit `Deny` or `Allow` decision was made,
    /// the function returns the value of `not_found`. If `not_found` is `true`, it means no
    /// applicable `Allow` strategy was found, and the function returns `true`. Otherwise, it returns `false`.
    ///
    /// # Arguments
    ///
    /// * `policies` - A slice of policy public keys to check against.
    /// * `identity` - The identity public key.
    ///
    /// # Returns
    ///
    /// `true` if the identity is allowed by any of the specified policies, `false` otherwise.
    pub fn is_allowed(&self, policies: &[Pubkey], identity: &Pubkey) -> Result<bool, CheckError> {
        let mut not_found = true;

        for address in policies.iter() {
            if let Some(strategy) = self.strategies.get(address) {
                if self.lookup.contains(&(*address, *identity)) {
                    match strategy {
                        PermissionStrategy::Deny => {
                            return Ok(false);
                        }
                        PermissionStrategy::Allow => {
                            return Ok(true);
                        }
                    }
                } else if let PermissionStrategy::Allow = strategy {
                    not_found = false;
                }
            } else {
                return Err(CheckError::PolicyNotFound);
            }
        }

        Ok(not_found)
    }
}

#[derive(Debug, Default)]
pub struct SlotRpcResponse<T> {
    slot: u64,
    result: T,
}

pub type PoliciesSlotRpcResponse = SlotRpcResponse<Vec<(Pubkey, Policy)>>;
pub struct PolicyRpcClient(RpcClient);

impl PolicyRpcClient {
    pub fn new(client: RpcClient) -> Self {
        Self(client)
    }

    pub async fn list(&self, program_id: &Pubkey) -> Result<PoliciesSlotRpcResponse> {
        let slot = self.0.get_slot().await?;

        let result = self
            .0
            .get_program_ui_accounts_with_config(
                program_id,
                RpcProgramAccountsConfig {
                    account_config: RpcAccountInfoConfig {
                        encoding: Some(UiAccountEncoding::Base64),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .filter_map(|(address, account)| {
                let account: Account = match account.to_account() {
                    Some(account) => account,
                    None => {
                        log::warn!("Failed to decode account data for {}", address);
                        return None;
                    }
                };
                let data: &[u8] = &account.data;
                let owner = &account.owner;

                match parse_account(slot, address, owner, data, Some(program_id)) {
                    Ok(ShieldProgramState::Policy(_slot, _pubkey, policy)) => {
                        Some((address, policy))
                    }
                    Err(e) => {
                        log::warn!("Failed to parse policy account {}: {}", address, e);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        Ok(SlotRpcResponse { slot, result })
    }
}

impl From<PoliciesSlotRpcResponse> for PolicyCache {
    fn from(response: PoliciesSlotRpcResponse) -> Self {
        let cache = Self::new();

        for (address, policy) in response.result.into_iter() {
            cache.insert(address, response.slot, policy);
        }

        cache
    }
}

pub trait PolicyStoreTrait {
    fn snapshot(&self) -> Arc<Snapshot>;
}

/// A structure that manages the caching and synchronization of identity policies.
pub struct PolicyStore {
    /// An atomic reference-counted snapshot of the current state of policies.
    snapshot: Arc<ArcSwap<Snapshot>>,
}

impl PolicyStore {
    /// Creates a new `PolicyStore` from a given set of policies.
    ///
    /// # Arguments
    ///
    /// * `policies` - A response containing policies and their associated slots.
    ///
    /// # Returns
    ///
    /// A new instance of `PolicyStore`.
    pub fn new(snapshot: Arc<ArcSwap<Snapshot>>) -> Self {
        Self { snapshot }
    }
}

impl PolicyStoreTrait for PolicyStore {
    fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.load_full()
    }
}

/// A mock implementation of PolicyStore for testing purposes.
pub struct MockPolicyStore {
    snapshot: Arc<Snapshot>,
}

impl MockPolicyStore {
    /// Creates a new `MockPolicyStore` with a given snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - An atomic reference-counted snapshot of the current state of policies.
    ///
    /// # Returns
    ///
    /// A new instance of `MockPolicyStore`.
    pub fn new(snapshot: Arc<Snapshot>) -> Self {
        Self { snapshot }
    }
}

impl PolicyStoreTrait for MockPolicyStore {
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot)
    }
}

pub type SubscriptionTask = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>;

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

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("No config provided")]
    NoConfig,
    #[error("Unable to deserialize policy")]
    DeserializePolicy,
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("gRPC client error: {0}")]
    GrpcClientError(String),
    #[error("gRPC connection error: {0}")]
    GrpcConnectionError(String),
    #[error("gRPC subscription error: {0}")]
    GrpcSubscriptionError(String),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

impl From<solana_client::client_error::ClientError> for StoreError {
    fn from(e: solana_client::client_error::ClientError) -> Self {
        StoreError::RpcError(e.to_string())
    }
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
    use solana_pubkey::Pubkey;
    use yellowstone_grpc_proto::{geyser::SubscribeUpdate, tonic};
    use yellowstone_shield_parser::accounts::Policy;

    #[test]
    fn test_policy_cache_insert_and_get() {
        let cache = PolicyCache::new();
        let address = Pubkey::new_unique();
        let validator = Pubkey::new_unique();
        let policy = Policy::new(PermissionStrategy::Deny, vec![validator]);

        cache.insert(address, 1, policy.clone());
        let retrieved_policy = cache.get(&address).unwrap();

        assert_eq!(retrieved_policy.strategy, policy.strategy);
        assert_eq!(retrieved_policy.identities, policy.identities);
    }

    #[test]
    fn test_policy_cache_all() {
        let cache = PolicyCache::new();
        let validator = Pubkey::new_unique();

        let policies = [
            (
                Pubkey::new_unique(),
                Policy::new(PermissionStrategy::Deny, vec![validator]),
            ),
            (
                Pubkey::new_unique(),
                Policy::new(PermissionStrategy::Allow, vec![validator]),
            ),
        ];

        for (pubkey, policy) in policies.iter() {
            cache.insert(*pubkey, 1, policy.clone());
        }

        let policies = cache.all();
        assert_eq!(policies.len(), 2);
    }

    #[test]
    fn test_policy_cache_remove() {
        let cache = PolicyCache::new();
        let address = Pubkey::new_unique();
        let validator = Pubkey::new_unique();
        let policy = Policy::new(PermissionStrategy::Deny, vec![validator]);

        cache.insert(address, 1, policy.clone());
        cache.remove(&address).unwrap();

        assert!(cache.get(&address).is_none());
    }

    #[test]
    fn test_snapshot_is_allowed() {
        let cache = PolicyCache::new();

        let deny = Pubkey::new_unique();
        let allow = Pubkey::new_unique();
        let missing = Pubkey::new_unique();

        let good = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let sanctioned = Pubkey::new_unique();
        let sandwich = Pubkey::new_unique();

        let policies = [
            (allow, Policy::new(PermissionStrategy::Allow, vec![good])),
            (
                deny,
                Policy::new(PermissionStrategy::Deny, vec![sanctioned, sandwich]),
            ),
        ];

        for (address, policy) in policies.into_iter() {
            cache.insert(address, 1, policy.clone());
        }
        let snapshot = Snapshot::new(&cache);

        assert_eq!(
            snapshot.is_allowed(&[missing], &good),
            Err(CheckError::PolicyNotFound)
        );
        assert_eq!(
            snapshot.is_allowed(&[missing, allow], &good),
            Err(CheckError::PolicyNotFound)
        );
        assert_eq!(snapshot.is_allowed(&[allow, missing], &good), Ok(true));
        assert_eq!(
            snapshot.is_allowed(&[deny, missing], &good),
            Err(CheckError::PolicyNotFound)
        );

        assert_eq!(snapshot.is_allowed(&[deny], &sanctioned), Ok(false));
        assert_eq!(snapshot.is_allowed(&[deny], &sandwich), Ok(false));
        assert_eq!(snapshot.is_allowed(&[deny], &good), Ok(true));
        assert_eq!(snapshot.is_allowed(&[deny], &other), Ok(true));

        assert_eq!(snapshot.is_allowed(&[allow], &good), Ok(true));
        assert_eq!(snapshot.is_allowed(&[allow], &sanctioned), Ok(false));
        assert_eq!(snapshot.is_allowed(&[allow], &sandwich), Ok(false));
        assert_eq!(snapshot.is_allowed(&[allow], &other), Ok(false));

        assert_eq!(snapshot.is_allowed(&[allow, deny], &other), Ok(false));
        assert_eq!(snapshot.is_allowed(&[allow, deny], &good), Ok(true));
        assert_eq!(snapshot.is_allowed(&[allow, deny], &sandwich), Ok(false));

        assert_eq!(snapshot.is_allowed(&[deny, allow], &other), Ok(false));
        assert_eq!(snapshot.is_allowed(&[deny, allow], &good), Ok(true));
        assert_eq!(snapshot.is_allowed(&[deny, allow], &sandwich), Ok(false));
    }

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
    fn test_policy_cache_remove_at_respects_slot() {
        let cache = PolicyCache::new();
        let address = Pubkey::new_unique();
        let policy = Policy::new(PermissionStrategy::Deny, vec![Pubkey::new_unique()]);

        cache.insert(address, 10, policy);

        assert!(!cache.remove_at(&address, 9));
        assert!(cache.get(&address).is_some());

        assert!(cache.remove_at(&address, 10));
        assert!(cache.get(&address).is_none());

        assert!(!cache.remove_at(&address, 11));
    }

    #[test]
    fn test_policy_cache_sync_removes_missing_policies() {
        let cache = PolicyCache::new();
        let kept = Pubkey::new_unique();
        let closed = Pubkey::new_unique();
        let newer = Pubkey::new_unique();
        let created = Pubkey::new_unique();
        let policy = Policy::new(PermissionStrategy::Deny, vec![Pubkey::new_unique()]);

        cache.insert(kept, 5, policy.clone());
        cache.insert(closed, 5, policy.clone());
        // Updated on the stream after the RPC listing was taken.
        cache.insert(newer, 20, policy.clone());

        cache.sync(PoliciesSlotRpcResponse {
            slot: 10,
            result: vec![(kept, policy.clone()), (created, policy)],
        });

        assert!(cache.get(&kept).is_some());
        assert!(cache.get(&created).is_some());
        assert!(cache.get(&newer).is_some());
        assert!(cache.get(&closed).is_none());
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

    #[test]
    fn test_mock_policy_store() {
        let snapshot = Arc::new(Snapshot::default());

        let store = MockPolicyStore::new(Arc::clone(&snapshot));

        let fetched = store.snapshot();

        assert!(std::sync::Arc::ptr_eq(&fetched, &snapshot));
    }
}
