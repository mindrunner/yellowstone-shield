use solana_account::Account;
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
};
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use yellowstone_shield_parser::accounts::{parse_account, ShieldProgramState};

use crate::{PoliciesSlotRpcResponse, Result, SlotRpcResponse, StoreError};

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

impl From<solana_client::client_error::ClientError> for StoreError {
    fn from(e: solana_client::client_error::ClientError) -> Self {
        StoreError::RpcError(e.to_string())
    }
}
