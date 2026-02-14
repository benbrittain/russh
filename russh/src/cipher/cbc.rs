use aes::cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt,
    BlockSizeUser, InnerIvInit, Iv, IvSizeUser,
    common::InnerUser,
};
use cbc::{Decryptor, Encryptor};

use super::block::BlockStreamCipher;

pub struct CbcWrapper<C: BlockCipherEncrypt + BlockSizeUser + BlockCipherDecrypt> {
    encryptor: Encryptor<C>,
    decryptor: Decryptor<C>,
}

impl<C: BlockCipherEncrypt + BlockSizeUser + BlockCipherDecrypt> InnerUser for CbcWrapper<C> {
    type Inner = C;
}

impl<C: BlockCipherEncrypt + BlockSizeUser + BlockCipherDecrypt> IvSizeUser for CbcWrapper<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockCipherEncrypt + BlockSizeUser + BlockCipherDecrypt> BlockStreamCipher
    for CbcWrapper<C>
{
    fn encrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            let mut block: Block<C> = (&*chunk).try_into().expect("block size mismatch");
            self.encryptor.encrypt_block_inout((&mut block).into());
            chunk.copy_from_slice(&block);
        }
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            let mut block: Block<C> = (&*chunk).try_into().expect("block size mismatch");
            self.decryptor.decrypt_block_inout((&mut block).into());
            chunk.copy_from_slice(&block);
        }
    }
}

impl<C: BlockCipherEncrypt + BlockSizeUser + BlockCipherDecrypt + Clone> InnerIvInit
    for CbcWrapper<C>
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: Encryptor::inner_iv_init(cipher.clone(), iv),
            decryptor: Decryptor::inner_iv_init(cipher, iv),
        }
    }
}
