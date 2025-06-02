use crate::error::ErrorCode;
use crate::states::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdatePoolStatus<'info> {
    #[account(
        address = admin_group.emergency_manager @ ErrorCode::NotApproved
    )]
    pub authority: Signer<'info>,

    /// amm admin group account to store admin permissions.
    #[account(
        seeds = [
            ADMIN_GROUP_SEED.as_bytes()
        ],
        bump,
    )]
    pub admin_group: Box<Account<'info, AmmAdminGroup>>,

    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,
}

pub fn update_pool_status(ctx: Context<UpdatePoolStatus>, status: u8) -> Result<()> {
    require_gte!(255, status);
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    pool_state.set_status(status);
    Ok(())
}
