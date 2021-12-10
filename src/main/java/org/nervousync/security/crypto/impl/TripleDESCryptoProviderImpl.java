package org.nervousync.security.crypto.impl;

import org.nervousync.security.config.CipherConfig;
import org.nervousync.security.crypto.SymmetricCryptoProvider;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public final class TripleDESCryptoProviderImpl extends SymmetricCryptoProvider {

    public TripleDESCryptoProviderImpl(CipherConfig cipherConfig, CryptoMode cryptoMode, byte[] keyBytes)
            throws CryptoException {
        super(cipherConfig, cryptoMode, new CipherKey(keyBytes));
    }

    @Override
    protected Cipher initCipher() throws CryptoException {
        try {
            DESedeKeySpec keySpec = new DESedeKeySpec(this.cipherKey.getKeyBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            return super.generateCipher(keyFactory.generateSecret(keySpec),
                    this.cipherConfig.getMode().equalsIgnoreCase("ECB") ? 0 : 8);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
