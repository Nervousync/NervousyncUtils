/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.nervousync.generator.uuid.impl;

import org.nervousync.annotations.provider.Provider;
import org.nervousync.generator.uuid.UUIDGenerator;
import org.nervousync.generator.uuid.timer.TimeSynchronizer;
import org.nervousync.utils.IDUtils;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.SystemUtils;

import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * <h2 class="en-US">UUID version 2 generator</h2>
 * <h2 class="zh-CN">UUID版本2生成器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:53:06 $
 */
@Provider(name = IDUtils.UUIDv2, titleKey = "version2.uuid.id.generator.name")
public final class UUIDv2Generator extends UUIDGenerator {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(UUIDv2Generator.class);

	/**
	 * <span class="en-US">UUID timer instance object</span>
	 * <span class="zh-CN">UUID时钟实例对象</span>
	 */
    private final UUIDTimer uuidTimer;

    /**
     * Instantiates a new Uui dv 2 generator.
     */
    public UUIDv2Generator() {
        this.uuidTimer = new UUIDTimer();
    }

    /**
	 * <h3 class="en-US">Configure current generator</h3>
	 * <h3 class="zh-CN">修改当前生成器的配置</h3>
     *
     * @param synchronizer  <span class="en-US">Time synchronizer instance</span>
     *                      <span class="zh-CN">时间同步器实例对象</span>
     */
    public void config(final TimeSynchronizer synchronizer) {
        this.uuidTimer.config(synchronizer);
    }
    /**
	 * <h3 class="en-US">Generate ID value</h3>
	 * <h3 class="zh-CN">生成ID值</h3>
     *
     * @return  <span class="en-US">Generated value</span>
     *          <span class="zh-CN">生成的ID值</span>
     */
    @Override
    public String generate() {
        return new UUID(super.highBits(this.uuidTimer.getTimestamp()), this.lowBits(SystemUtils.localMac())).toString();
    }
    /**
	 * <h3 class="en-US">Generate ID value using given parameter</h3>
	 * <h3 class="zh-CN">使用给定的参数生成ID值</h3>
     *
     * @param dataBytes     <span class="en-US">Given parameter</span>
     *                      <span class="zh-CN">给定的参数</span>
     *
     * @return  <span class="en-US">Generated value</span>
     *          <span class="zh-CN">生成的ID值</span>
     */
    @Override
    public String generate(byte[] dataBytes) {
        return this.generate();
    }
    /**
	 * <h3 class="en-US">Calculate low bits of given data bytes</h3>
	 * <h3 class="zh-CN">从给定的二进制数组计算低位值</h3>
     *
     * @param dataBytes     <span class="en-US">given data bytes</span>
     *                      <span class="zh-CN">给定的二进制数组</span>
     * @return  <span class="en-US">Low bits value in long</span>
     *          <span class="zh-CN">long型的低位比特值</span>
     */
    @Override
    protected long lowBits(byte[] dataBytes) {
        if (dataBytes.length != 6) {
            throw new IllegalArgumentException("Illegal offset, need room for 6 bytes");
        }
        long address = dataBytes[0] & 255;

        for (int i = 1; i < 6; ++i) {
            address = address << 8 | (long) (dataBytes[i] & 255);
        }

        int i = (int) (address >> 32);
        byte[] uuidBytes = new byte[16];
        int pos = 10;
        uuidBytes[pos++] = (byte) (i >> 8);
        uuidBytes[pos++] = (byte) i;
        i = (int) address;
        uuidBytes[pos++] = (byte) (i >> 24);
        uuidBytes[pos++] = (byte) (i >> 16);
        uuidBytes[pos++] = (byte) (i >> 8);
        uuidBytes[pos] = (byte) i;

        int sequence = uuidTimer.clockSequence();
        uuidBytes[8] = (byte) (sequence >> 8);
        uuidBytes[9] = (byte) sequence;

        long lowBits = (toLong(uuidBytes, 8) << 32) | (toLong(uuidBytes, 12) << 32 >>> 32);
        lowBits = lowBits << 2 >>> 2;
        lowBits |= -9223372036854775808L;
        return lowBits;
    }
    /**
	 * <h3 class="en-US">Destroy current generator instance</h3>
	 * <h3 class="zh-CN">销毁当前生成器实例对象</h3>
     */
    @Override
    public void destroy() {
        this.uuidTimer.destroy();
    }

    private static long toLong(byte[] buffer, int offset) {
        return buffer[offset] << 24 | (buffer[offset + 1] & 255) << 16
                | (buffer[offset + 2] & 255) << 8 | buffer[offset + 3] & 255;
    }

    private static final class UUIDTimer {

        private TimeSynchronizer synchronizer;
        private Random random;
        private int sequence;
        private long systemTimestamp;
        private long usedTimestamp;
        private long unsafeTimestamp;
        private int counter = 0;
        private static final int MAX_WAIT_COUNT = 50;

        /**
         * Instantiates a new Uuid timer.
         */
        public UUIDTimer() {
            this.config(null);
        }

        /**
         * Config.
         *
         * @param synchronizer the synchronizer
         */
        public void config(final TimeSynchronizer synchronizer) {
            if (this.synchronizer == null || !this.synchronizer.equals(synchronizer)) {
                this.synchronizer = synchronizer;
            }
            this.init();
        }

        private void init() {
            this.random = new Random(System.currentTimeMillis());
            this.initCounters();
            this.systemTimestamp = 0L;
            this.usedTimestamp = 0L;
            if (this.synchronizer != null) {
                long initTimestamp = this.synchronizer.initialize();
                if (initTimestamp > this.usedTimestamp) {
                    this.usedTimestamp = initTimestamp;
                }
            }
            this.unsafeTimestamp = 0L;
        }

        /**
         * Clock sequence int.
         *
         * @return the int
         */
        public int clockSequence() {
            return this.sequence & '\uFFFF';
        }

        /**
         * Gets timestamp.
         *
         * @return the timestamp
         */
        public synchronized long getTimestamp() {
            long currentTimeMillis = System.currentTimeMillis();
            if (currentTimeMillis < this.systemTimestamp) {
                LOGGER.warn("Go_Back_Time_UUID_Debug",
                        currentTimeMillis, this.systemTimestamp);
                this.systemTimestamp = currentTimeMillis;
            }

            if (currentTimeMillis <= this.usedTimestamp) {
                if (this.counter < 10000) {
                    currentTimeMillis = this.usedTimestamp;
                } else {
                    long actDiff = this.usedTimestamp - currentTimeMillis;
                    long origTime = currentTimeMillis;
                    currentTimeMillis = this.usedTimestamp + 1L;
                    LOGGER.warn("Timestamp_Over_Run_Warn");
                    this.initCounters();
                    if (actDiff >= 100L) {
                        slowDown(origTime, actDiff);
                    }
                }
            } else {
                this.counter &= 255;
            }

            this.usedTimestamp = currentTimeMillis;
            if (this.synchronizer != null && currentTimeMillis >= this.unsafeTimestamp) {
                this.unsafeTimestamp = this.synchronizer.update(currentTimeMillis);
            }

            currentTimeMillis *= 10000L;
            currentTimeMillis += 122192928000000000L;
            currentTimeMillis += this.counter;
            ++this.counter;
            return currentTimeMillis;
        }

        private void initCounters() {
            this.sequence = this.random.nextInt();
            this.counter = this.sequence >> 16 & 255;
        }

        private void slowDown(long startTime, long actDiff) {
            long ratio = actDiff / 100L;
            long delayMillis;
            if (ratio < 2L) {
                delayMillis = 1L;
            } else if (ratio < 10L) {
                delayMillis = 2L;
            } else if (ratio < 600L) {
                delayMillis = 3L;
            } else {
                delayMillis = 5L;
            }

            LOGGER.warn("Virtual_Clock_Warn", delayMillis);
            long timeOutMillis = startTime + delayMillis;
            int counter = 0;

            while (counter <= MAX_WAIT_COUNT && System.currentTimeMillis() < timeOutMillis) {
                try {
                    TimeUnit.MILLISECONDS.sleep(delayMillis);
                } catch (InterruptedException ignored) {
                }
                delayMillis = 1L;
                counter++;
            }
        }

        void destroy() {
            if (this.synchronizer != null) {
                this.synchronizer.deactivate();
            }
        }
    }
}
