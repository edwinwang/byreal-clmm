use std::cell::{Ref, RefMut};

use crate::error::ErrorCode as ClmmErrorCode;
use crate::util::*;
use anchor_lang::error::{Error, ErrorCode};
use anchor_lang::prelude::*;
use arrayref::array_ref;

use crate::states::*;

#[account(zero_copy)]
#[repr(C, packed)]
pub struct DynTickArrayState {
    pub pool_id: Pubkey,
    pub start_tick_index: i32,
    pub padding_0: [u8; 4],
    // tick_offset_index[0] is position+1 of start_tick_index
    // tick_offset_index[n] is position+1 of start_tick_index + n * tick_spacing
    // position: means the index in TickState array, which follows this header
    // ...
    // 0 means this tick is not allocated
    pub tick_offset_index: [u8; TICK_ARRAY_SIZE_USIZE],
    /// how many ticks are allocated in this tick array
    pub alloc_tick_count: u8,
    /// how many ticks are initialized in this tick array
    pub initialized_tick_count: u8,
    pub padding_1: [u8; 2],
    // account update recent epoch
    pub recent_epoch: u64,
    // Unused bytes for future upgrades.
    pub padding_2: [u8; 96],
}
// TickState array, max size is TICK_ARRAY_SIZE_USIZE

impl Default for DynTickArrayState {
    fn default() -> Self {
        Self {
            pool_id: Pubkey::default(),
            start_tick_index: 0,
            padding_0: [0; 4],
            tick_offset_index: [0; TICK_ARRAY_SIZE_USIZE],
            alloc_tick_count: 0,
            initialized_tick_count: 0,
            padding_1: [0; 2],
            recent_epoch: 0,
            padding_2: [0; 96],
        }
    }
}

impl DynTickArrayState {
    pub const HEADER_LEN: usize = 8 + std::mem::size_of::<DynTickArrayState>();

    // when first create, we only allocate space for header + one TickState
    pub const FIRST_CREATE_LEN: usize = Self::HEADER_LEN + TickState::LEN;

    pub fn all_data_len(&self) -> usize {
        Self::HEADER_LEN + self.alloc_tick_count as usize * TickState::LEN
    }

    pub fn initialize(&mut self, start_index: i32, tick_spacing: u16, pool_key: Pubkey) -> Result<()> {
        TickUtils::check_is_valid_start_index(start_index, tick_spacing);
        self.start_tick_index = start_index;
        self.pool_id = pool_key;
        self.recent_epoch = get_recent_epoch()?;

        Ok(())
    }

    /// Mark a TickState as used in this tick array.
    /// return the offset index of this tick in the TickState array
    pub fn use_one_tick(&mut self, tick_index: i32, tick_spacing: u16) -> Result<u8> {
        let offset = TickUtils::get_tick_offset_in_tick_array(self.start_tick_index, tick_index, tick_spacing)?;

        require!(self.tick_offset_index[offset] == 0, ClmmErrorCode::InvalidTickIndex);

        self.alloc_tick_count += 1;
        self.tick_offset_index[offset] = self.alloc_tick_count;

        let tick_state_index = self.alloc_tick_count - 1;

        Ok(tick_state_index)
    }

    /// Get the index of a tick in the TickState array.
    /// The TickState array is placed after the header in the account data.
    pub fn get_tick_index_in_array(&self, tick_index: i32, tick_spacing: u16) -> Result<u8> {
        let offset = TickUtils::get_tick_offset_in_tick_array(self.start_tick_index, tick_index, tick_spacing)?;

        let tick_state_index = self.tick_offset_index[offset];
        require!(tick_state_index > 0, ClmmErrorCode::InvalidTickIndex);

        Ok(tick_state_index - 1)
    }

    pub fn next_initialized_tick_index(
        &mut self,
        current_tick_index: i32,
        tick_spacing: u16,
        zero_for_one: bool,
    ) -> Result<Option<u8>> {
        let current_tick_array_start_index = TickUtils::get_array_start_index(current_tick_index, tick_spacing);
        if current_tick_array_start_index != self.start_tick_index {
            return Ok(None);
        }
        let mut offset_in_array = (current_tick_index - self.start_tick_index) / i32::from(tick_spacing);

        if zero_for_one {
            while offset_in_array >= 0 {
                if self.tick_offset_index[offset_in_array as usize] > 0 {
                    return Ok(Some(self.tick_offset_index[offset_in_array as usize] - 1));
                }
                offset_in_array = offset_in_array - 1;
            }
        } else {
            offset_in_array = offset_in_array + 1;
            while offset_in_array < TICK_ARRAY_SIZE {
                if self.tick_offset_index[offset_in_array as usize] > 0 {
                    return Ok(Some(self.tick_offset_index[offset_in_array as usize] - 1));
                }
                offset_in_array = offset_in_array + 1;
            }
        }
        Ok(None)
    }

    /// Base on swap directioin, return the first initialized tick in the tick array.
    pub fn first_initialized_tick_index(&mut self, zero_for_one: bool) -> Result<u8> {
        if zero_for_one {
            let mut i = TICK_ARRAY_SIZE - 1;
            while i >= 0 {
                if self.tick_offset_index[i as usize] > 0 {
                    return Ok(self.tick_offset_index[i as usize] - 1);
                }
                i = i - 1;
            }
        } else {
            let mut i = 0;
            while i < TICK_ARRAY_SIZE_USIZE {
                if self.tick_offset_index[i] > 0 {
                    return Ok(self.tick_offset_index[i] - 1);
                }
                i = i + 1;
            }
        }
        err!(ClmmErrorCode::InvalidTickArray)
    }
}

/// Loader for dynamic TickArray accounts
#[derive(Clone)]
pub struct DynTickArrayLoader<'info> {
    acc_info: AccountInfo<'info>,
}

/// static methods
impl<'info> DynTickArrayLoader<'info> {
    pub fn new(acc_info: AccountInfo<'info>) -> Self {
        Self { acc_info }
    }

    /// Constructs a new `Loader` from a previously initialized account.
    #[inline(never)]
    pub fn try_from(acc_info: &AccountInfo<'info>) -> Result<Self> {
        if acc_info.owner != &crate::id() {
            return Err(Error::from(ErrorCode::AccountOwnedByWrongProgram).with_pubkeys((*acc_info.owner, crate::id())));
        }
        let data: &[u8] = &acc_info.try_borrow_data()?;
        if data.len() < DynTickArrayState::DISCRIMINATOR.len() {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }
        // Discriminator must match.
        let disc_bytes = array_ref![data, 0, 8];
        if disc_bytes != &DynTickArrayState::DISCRIMINATOR {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        Ok(Self::new(acc_info.clone()))
    }

    /// Constructs a new `Loader` from an uninitialized account.
    #[inline(never)]
    pub fn try_from_unchecked(acc_info: &AccountInfo<'info>) -> Result<Self> {
        if acc_info.owner != &crate::id() {
            return Err(Error::from(ErrorCode::AccountOwnedByWrongProgram).with_pubkeys((*acc_info.owner, crate::id())));
        }
        Ok(Self::new(acc_info.clone()))
    }
}

/// member methods
impl<'info> DynTickArrayLoader<'info> {
    /// Returns a `RefMut` to the account data structure for reading or writing.
    /// Should only be called once, when the account is being initialized.
    pub fn load_init<'a>(&'a self) -> Result<(RefMut<'a, DynTickArrayState>, RefMut<'a, [TickState]>)> {
        // AccountInfo api allows you to borrow mut even if the account isn't
        // writable, so add this check for a better dev experience.
        if !self.acc_info.is_writable {
            return Err(ErrorCode::AccountNotMutable.into());
        }

        let mut data = self.acc_info.try_borrow_mut_data()?;

        // The discriminator should be zero, since we're initializing.
        let mut disc_bytes = [0u8; 8];
        disc_bytes.copy_from_slice(&data[..8]);
        let discriminator = u64::from_le_bytes(disc_bytes);
        if discriminator != 0 {
            return Err(ErrorCode::AccountDiscriminatorAlreadySet.into());
        }

        // write discriminator
        data[..8].copy_from_slice(&DynTickArrayState::DISCRIMINATOR);

        // split the data into header and ticks part
        if data.len() < DynTickArrayState::HEADER_LEN {
            return Err(ErrorCode::AccountDidNotDeserialize.into());
        }

        let (header, ticks) = RefMut::map_split(data, |data_slice| {
            let (header_bytes, ticks_bytes) = data_slice.split_at_mut(DynTickArrayState::HEADER_LEN);

            // 将字节切片转换为对应的可变结构体引用
            let header: &mut DynTickArrayState = bytemuck::from_bytes_mut(header_bytes[8..].as_mut());

            let ticks: &mut [TickState] =
                bytemuck::try_cast_slice_mut(ticks_bytes).expect("Failed to cast ticks_bytes to TickState slice");

            (header, ticks)
        });

        Ok((header, ticks))
    }

    /// Returns a `RefMut` to the account data structure for reading or writing.
    /// Should only be called once, when the account is being initialized.
    pub fn load_mut<'a>(&'a self) -> Result<(RefMut<'a, DynTickArrayState>, RefMut<'a, [TickState]>)> {
        // AccountInfo api allows you to borrow mut even if the account isn't
        // writable, so add this check for a better dev experience.
        if !self.acc_info.is_writable {
            return Err(ErrorCode::AccountNotMutable.into());
        }

        let data = self.acc_info.try_borrow_mut_data()?;
        let data_len = data.len();

        let (header, ticks) = RefMut::map_split(data, |data_slice| {
            let (header_bytes, ticks_bytes) = data_slice.split_at_mut(DynTickArrayState::HEADER_LEN);

            // 将字节切片转换为对应的可变结构体引用
            let header: &mut DynTickArrayState = bytemuck::from_bytes_mut(header_bytes[8..].as_mut());

            let ticks: &mut [TickState] =
                bytemuck::try_cast_slice_mut(ticks_bytes).expect("Failed to cast ticks_bytes to TickState slice");

            (header, ticks)
        });

        if data_len != header.all_data_len() {
            return Err(ErrorCode::AccountDidNotDeserialize.into());
        }

        Ok((header, ticks))
    }

    /// Returns a Ref to the account data structure for reading.
    pub fn load<'a>(&'a self) -> Result<(Ref<'a, DynTickArrayState>, Ref<'a, [TickState]>)> {
        let data = self.acc_info.try_borrow_data()?;
        let data_len = data.len();
        if data_len < DynTickArrayState::DISCRIMINATOR.len() {
            return Err(ErrorCode::AccountDiscriminatorNotFound.into());
        }

        let disc_bytes = array_ref![data, 0, 8];
        if disc_bytes != &DynTickArrayState::DISCRIMINATOR {
            return Err(ErrorCode::AccountDiscriminatorMismatch.into());
        }

        let (header, ticks) = Ref::map_split(data, |data_slice| {
            let (header_bytes, ticks_bytes) = data_slice.split_at(DynTickArrayState::HEADER_LEN);

            // 将字节切片转换为对应的可变结构体引用
            let header: &DynTickArrayState = bytemuck::from_bytes(header_bytes[8..].as_ref());

            let ticks: &[TickState] =
                bytemuck::try_cast_slice(ticks_bytes).expect("Failed to cast ticks_bytes to TickState slice");

            (header, ticks)
        });

        if data_len != header.all_data_len() {
            return Err(ErrorCode::AccountDidNotDeserialize.into());
        }

        Ok((header, ticks))
    }
}
