use crate::states::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CloseProtocolPositionAccounts<'info> {
    /// amm admin group account to store admin permissions.
    /// anyone can collect fee, but only fee-manager in admin group can receive fee
    #[account(
        seeds = [
            ADMIN_GROUP_SEED.as_bytes()
        ],
        bump,
    )]
    pub admin_group: Box<Account<'info, AmmAdminGroup>>,

    /// CHECK: fee keeper to receive the remaining fund fee
    #[account(
        mut,
        address = admin_group.fee_keeper,
    )]
    pub fee_keeper: UncheckedAccount<'info>,

    #[account(
        mut,
        close = fee_keeper,
    )]
    pub protocol_position: Account<'info, ProtocolPositionState>,

    pub system_program: Program<'info, System>,
}

/// close the protocol position, send the remaining fund fee to admin fee keeper
/// this instruction will be delete after all protocol position is closed
pub fn close_protocol_position(_ctx: Context<CloseProtocolPositionAccounts>) -> Result<()> {
    Ok(())
}
