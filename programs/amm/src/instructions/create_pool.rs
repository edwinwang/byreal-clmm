use super::create_pool_decay_fee::*;
use anchor_lang::{prelude::*, solana_program};

pub fn create_pool(ctx: Context<CreatePool>, sqrt_price_x64: u128, open_time: u64) -> Result<()> {
    // we can set open-time as a future time, or current time
    let block_timestamp = solana_program::clock::Clock::get()?.unix_timestamp as u64;
    let open_time = if open_time > block_timestamp {
        open_time
    } else {
        block_timestamp
    };

    let params = CreatePoolDecayFeeParams {
        sqrt_price_x64,
        open_time: Some(open_time),
        // don't use dynamic fee for the pool in this instruction
        use_decay_fee: false,
        ..Default::default()
    };

    create_pool_decay_fee(ctx, params)?;
    Ok(())
}
