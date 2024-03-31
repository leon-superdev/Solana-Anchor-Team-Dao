// Import anchor
use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    metadata::{
        create_master_edition_v3, create_metadata_accounts_v3, CreateMasterEditionV3,
        CreateMetadataAccountsV3, Metadata, 
    }, 
    token::{mint_to, Mint, MintTo, Token, TokenAccount},
};

use mpl_token_metadata::{
    pda::{find_master_edition_account, find_metadata_account},
    state::DataV2,
};
use solana_program::clock::Clock;
declare_id!("BqJtqJMXg6rnKuvFb8d5ZnaUSdNWScsDAA2doFzZE8N3");


const ADMIN_PUBKEY: Pubkey = pubkey!("GiBrvqu88cyzyVpmqrqXN6T2n3cVBXbdwc696YjaV17E");

#[program]
pub mod dao {
    use super::*;

    pub fn init_mint_authority(
        ctx: Context<InitMintAuthority>,
    ) -> Result<()> {
        ctx.accounts.mint_authority.admin = ctx.accounts.signer.key(); 
        ctx.accounts.token_holder_num.number = 0;
        let user = &mut ctx.accounts.user;
        user.pubkey = ctx.accounts.signer.key();
        user.role = 2;
        user.name = "admin".to_string();
        Ok(())
    }

    pub fn create_mint(
        ctx: Context<CreateMint>,
        uri: String,
        name: String,
        symbol: String,
    ) -> Result<()> {
        // mint 1000 token to program account
        let cpi_context = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.spl_mint_account,
                to: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            }
        );

        mint_to(cpi_context, 1000);

        //create metadata account

        let cpi_context = CpiContext::new(
            ctx.accounts.token_metadata_program.to_account_info(),
            CreateMetadataAccountsV3 {
                metadata: ctx.accounts.spl_metadata_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                mint_authority: ctx.accounts.mint_authority.to_account_info(),
                update_authority: ctx.accounts.mint_authority.to_account_info(),
                payer: ctx.accounts.signer.to_account_info(),
                system_program: ctx.accounts.system_program.to_account_info(),
                rent: ctx.accounts.rent.to_account_info(),                
            },
        );
            // let seeds = b"mintauthority";
            // let bump = ctx.bumps.mint_authority;
            // let signer: &[&[&[u8]]] = &[&[seeds, &[bump]]];

        let data_v2 = DataV2 {
            name: name,
            symbol: symbol,
            uri: uri,
            seller_fee_basis_points: 0,
            creators: None,
            collections: None,
            uses: None
        };

        create_metadata_accounts_v3(cpi_context, data_v2, false, true, None)?;

        // create master edition account

        let cpi_context = CpiContext::new(
            ctx.accounts.token_metadata_program.to_account_info(),
            CreateMasterEditionV3 {
                edition: ctx.accounts.spl_master_edition_account.to_account_info(),
                mint: ctx.accounts.spl_mint_account.to_account_info(),
                update_authority: ctx.accounts.mint_authority.to_account_info(),
                mint_authority: ctx.accounts.mint_authority.to_account_info(),
                payer: ctx.accounts.signer.to_account_info(),
                metadata: ctx.accounts.spl_metadata_account.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
                system_program: ctx.accounts.system_program.to_account_info(),
                rent: ctx.accounts.rent.to_account_info(),
            },
        );
        create_master_edition_v3(cpi_context, None);
        Ok(())
    }

    pub fn create_user_account(
        ctx: Context<CreateUserAccount>,
        username: String,
    ) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        user.name = username;
        user.pubkey = ctx.accounts.signer.key();
        user.role = 0;
        Ok(())
    }

    pub fn activate_user(
        ctx: Context<ActivateUser>,
        _userkey: Pubkey,
    ) -> Result<()> {
        if ctx.accounts.signer.key() != ctx.accounts.mint_authority.admin {
            return err!(ErrorCode::NotAdmin);
        }
        ctx.accounts.user_account.role = 1;
        Ok(())
    }

    pub fn disable_user(
        ctx: Context<DisableUser>,
        _userkey: Pubkey,
    ) -> Result<()> {
        if ctx.accounts.signer.key() != ctx.accounts.mint_authority.admin {
            return err!(ErrorCode::NotAdmin);
        }
        ctx.accounts.user_account.role = 0;
        Ok(())
    }

    pub fn createProposal(
        ctx: Context<CreateProposal>,
        title: String,
        desc: String,
    ) -> Result<()> {
        let proposal = &mut ctx.accounts.proposal_pda;
        proposal.timestamp = Clock::get().unix_timestamp;
        proposal.pubkey = ctx.accounts.proposal_pda.key();
        proposal.desc = desc;
        proposal.title = title;
        Ok(())
    }
    
}

#[derive(Accounts)]
pub struct InitMintAuthority<'info> {
    #[account(
        init,
        payer = signer,
        seeds=[b"mint"],
        bump,
        space = 8 + 32
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    #[account(
        init,
        payer = signer,
        seeds=[b"user", signer.key().as_ref()],
        bump,
        space = 8 + 4 + 20 + 32 + 1
    )]
    pub user: Account<'info, User>,
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
    #[account(
        init,
        payer = signer,
        seeds=[b"tokenholdernum", signer.key.as_ref()],
        bump,
        space = 8 + 8
    )]
    pub token_holder_num: Account<'info, TokenHolderNum>,
} 

#[derive(Accounts)]
pub struct CreateMint<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        seeds=[b"mintauthority"],
        bump,
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    #[account(
        init,
        seeds=[b"mint"],
        bump,
        payer = signer,
        mint::decimals = 2,
        mint::authority = mint_authority,
    )]
    pub spl_mint_account: Account<'info, Mint>,
    ///CHECK: Using "address" constraint to validate metadata account address
    #[account(
        mut,
        address=find_metadata_account(&spl_mint_account.key()).0
    )]
    pub spl_metadata_account: UncheckAcount<'info>,
    /// CHECK: address
    #[account(
        mut,
        address=find_master_edition_account(&spl_mint_account.key()).0
    )],
    pub spl_master_edition_account: UncheckAcount<'info>,
    #[account(
        init,
        seeds=[b"splpda"],
        bump,
        payer = signer,
        space = 8 + 4 + 20,
    )]
    pub splpda: Account<'info, SPLPDA>,
    #[account(
        init,
        payer = signer,
        associated_token::mint = spl_mint_account,
        associated_token::authority = splpda,
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub token_metadata_program: Program<'info, Metadata>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
pub struct CreateUserAccount<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        init,
        seeds=[b"user", signer.key().as_ref()],
        bump,
        payer = signer,
        space = 8 + 4 + 20 + 32 + 1,
    )]
    pub user_account: Account<'info, User>,
    #[account(
        seeds=[b"mintauthority"],
        bump
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    #[account(
        init,
        payer = signer,
        associated_token::mint = spl_mint_account,
        associated_token::authority = signer,
    )]
    pub user_token_account: Account<'info, TokenAccount>
    #[account(
        seeds=[b"mint"],
        bump,
    )]
    pub spl_mint_account: Account<'info, Mint>,
    pub system_program: Program<'info, System>,
}
#[derive(Accounts)]
#[instruction(_userkey: Pubkey)]
pub struct ActivateUser<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        seeds=[b"mintauthority"],
        bump
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    #[account(
        mut,
        seeds=[b"user", _userkey.as_ref()],
        bump,
        
    )]
    pub user_account: Account<'info, User>,
    pub system_program: Program<'info, System>,
}
#[derive(Accounts)]
#[instruction(_userkey: Pubkey)]
pub struct DisableUser<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        seeds=[b"mintauthority"],
        bump
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    #[account(
        mut,
        seeds=[b"user", _userkey.as_ref()],
        bump,
        
    )]
    pub user_account: Account<'info, User>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateProposal<'info> {
    #[account(
        init,
        payer = signer,
        seeds = [b"proposal",  &Clock::get().unix_timestamp.to_le_bytes()],
        bump,
        space = 8 + 4 + 20 + 4 + 50 + 8 + 32
    )]
    pub proposal_pda: Account<'info, Proposal>,
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        seeds=[b"mintauthority"],
        bump,
        constraint = mint_authority.admin = signer.key(),
    )]
    pub mint_authority: Account<'info, MintAuthrity>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct MintAuthrity {
    admin: Pubkey,
}

#[account]
pub struct User {
    pubkey: Pubkey,
    name: String,
    role: u8,//0: non-active, 1: active; 2: admin    
}
#[account]
pub struct TokenHolderNum {
    number: u64,
}
#[account]
pub struct Proposal {
    pubkey: Pubkey,
    title: String,
    desc: String,
    timestamp: i64,
}
// #[account]
// pub struct NftPDA {
//     desc: String,
// }
#[account]
pub struct SPLPDA {
    desc: String,
}
#[error_code]
pub enum ErrorCode {
    #[msg("not admin!")]
    NotAdmin,
}