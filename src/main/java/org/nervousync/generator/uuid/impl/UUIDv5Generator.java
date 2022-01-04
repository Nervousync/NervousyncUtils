package org.nervousync.generator.uuid.impl;

import org.nervousync.annotations.generator.GeneratorProvider;
import org.nervousync.commons.core.Globals;
import org.nervousync.generator.uuid.UUIDGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@GeneratorProvider("UUIDv5")
public final class UUIDv5Generator extends UUIDGenerator {

    @Override
    public void initialize() {
    }

    @Override
    public Object random() {
        return this.random(new byte[0]);
    }

    @Override
    public Object random(byte[] dataBytes) {
        try {
            byte[] randomBytes = MessageDigest.getInstance("SHA1").digest(dataBytes);
            randomBytes[6] &= 0x0F;     /* clear version        */
            randomBytes[6] |= 0x40;     /* set to version 4     */
            randomBytes[8] &= 0x3F;     /* clear variant        */
            randomBytes[8] |= 0x80;     /* set to IETF variant  */
            return new UUID(super.highBits(randomBytes), super.lowBits(randomBytes)).toString();
        } catch (NoSuchAlgorithmException e) {
            return Globals.DEFAULT_VALUE_STRING;
        }
    }
}