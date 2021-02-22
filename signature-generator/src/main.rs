use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hex_literal::hex;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn main() {
    let key = hex!("cf22c8ae638db77f7a5cd61e110e870e01d7b6485d153dae38659ac900867ed5");
    let iv = hex!("f82606c5dde2f0e1eec388f9985e07c3");
    let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
    println!(
        "{}{}",
        hex::encode(iv),
        hex::encode(
            cipher
                .encrypt_vec(b"olavesctf{you_completed_this_padding_oracle_attack!_WELL_DONE!!!}")
        )
    );
}
