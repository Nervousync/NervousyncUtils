package org.nervousync.generator.uuid.impl;

import org.nervousync.annotations.generator.GeneratorProvider;
import org.nervousync.commons.core.Globals;
import org.nervousync.generator.uuid.UUIDGenerator;
import org.nervousync.utils.StringUtils;
import org.nervousync.utils.SystemUtils;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

@GeneratorProvider("UUIDv1")
public final class UUIDv1Generator extends UUIDGenerator {

    private static final long INTERVAL = 0x01B21DD213814000L;

    public static final String UUID_SEQUENCE = "org.nervousync.uuid.UUIDSequence";
    private static final String ASSIGNED_SEQUENCES = "org.nervousync.uuid.AssignedSequences";

    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicInteger generateCount = new AtomicInteger(0);

    @Override
    public void initialize() {
    }

    @Override
    public Object random() {
        return new UUID(super.highBits(this.currentTimeMillis()), this.lowBits(SystemUtils.localMac())).toString();
    }

    @Override
    public Object random(byte[] dataBytes) {
        return this.random();
    }

    @Override
    protected long lowBits(byte[] dataBytes) {
        if (dataBytes == null || dataBytes.length == 0) {
            dataBytes = new byte[6];
            this.secureRandom.nextBytes(dataBytes);
        }
        final int length = Math.min(dataBytes.length, 6);
        final int srcPos = dataBytes.length >= 6 ? dataBytes.length - 6 : 0;
        final byte[] node = new byte[]{(byte) 0x80, 0, 0, 0, 0, 0, 0, 0};
        System.arraycopy(dataBytes, srcPos, node, 2, length);
        final ByteBuffer byteBuffer = ByteBuffer.wrap(node);
        String assigned = System.getProperty(ASSIGNED_SEQUENCES, Globals.DEFAULT_VALUE_STRING);
        long[] sequences;
        if (StringUtils.isEmpty(assigned)) {
            sequences = new long[0];
        } else {
            final String[] array =
                    StringUtils.tokenizeToStringArray(assigned, Globals.DEFAULT_SPLIT_SEPARATOR);
            sequences = new long[array.length];
            final AtomicInteger index = new AtomicInteger(0);
            Arrays.stream(array).forEach(splitItem ->
                    sequences[index.getAndIncrement()] = Long.parseLong(splitItem));
        }

        long rand = Long.parseLong(System.getProperty(UUID_SEQUENCE, "0"));
        if (rand == 0L) {
            rand = this.secureRandom.nextLong();
        }
        rand &= 0x3FFF;
        boolean duplicate;
        do {
            duplicate = false;
            for (final long sequence : sequences) {
                if (sequence == rand) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                rand = (rand + 1) & 0x3FFF;
            }
        } while (duplicate);
        assigned = (StringUtils.isEmpty(assigned) ? Long.toString(rand) : assigned) + ',' + rand;
        System.setProperty(ASSIGNED_SEQUENCES, assigned);

        return (byteBuffer.getLong() | rand << 48);
    }

    private long currentTimeMillis() {
        return ((System.currentTimeMillis() * 10000) + INTERVAL) + (this.generateCount.incrementAndGet() % 10000);
    }
}
