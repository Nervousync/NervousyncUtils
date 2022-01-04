package org.nervousync.security.crypto.impl;

import org.nervousync.security.config.CipherConfig;
import org.nervousync.security.crypto.SymmetricCryptoProvider;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class AESCryptoProviderImpl extends SymmetricCryptoProvider {

    public AESCryptoProviderImpl(CipherConfig cipherConfig, CryptoMode cryptoMode, byte[] keyBytes)
            throws CryptoException {
        super(cipherConfig, cryptoMode, new CipherKey(keyBytes));
    }

    @Override
    protected Cipher initCipher() throws CryptoException {
        return super.generateCipher(new SecretKeySpec(this.cipherKey.getKeyBytes(), "AES"),
                this.cipherConfig.getMode().equalsIgnoreCase("ECB") ? 0 : 16);
    }
}