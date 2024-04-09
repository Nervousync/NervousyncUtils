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
package org.nervousync.generator.snowflake;

import org.nervousync.annotations.provider.Provider;
import org.nervousync.commons.Globals;
import org.nervousync.generator.IGenerator;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.IDUtils;
import org.nervousync.utils.LoggerUtils;

/**
 * <h2 class="en-US">SnowflakeID generator</h2>
 * <h2 class="zh-CN">雪花ID生成器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:44:27 $
 */
@Provider(name = IDUtils.SNOWFLAKE, titleKey = "snowflake.id.generator.name")
public final class SnowflakeGenerator implements IGenerator<Long> {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
    /**
     * <span class="en-US">Default value of ID</span>
     * <span class="zh-CN">默认的ID值</span>
     */
    private static final long DEFAULT_ID = 1L;
    /**
     * <span class="en-US">Sequence mask code, sequence id bits: 12</span>
     * <span class="zh-CN">序号掩码值，序号ID占用位数：12</span>
     */
    private static final long SEQUENCE_MASK = ~(-1L << 12L);
    /**
     * <span class="en-US">Node device ID (between 0 and 63), default value: 1L</span>
     * <span class="zh-CN">节点的机器ID（取值范围：0到63），默认值：1L</span>
     */
    private long deviceId = DEFAULT_ID;
    /**
     * <span class="en-US">Node instance ID (between 0 and 63), default value: 1L</span>
     * <span class="zh-CN">节点的实例ID（取值范围：0到63），默认值：1L</span>
     */
    private long instanceId = DEFAULT_ID;
    /**
     * <span class="en-US">Reference time, default value: 1303315200000L</span>
     * <span class="zh-CN">起始时间戳，默认值：1303315200000L</span>
     */
    private long referenceTime = Globals.DEFAULT_REFERENCE_TIME;
    /**
     * <span class="en-US">Sequence index of current time</span>
     * <span class="zh-CN">当前时间的序列索引</span>
     */
    private long sequenceIndex = 0L;
    /**
     * <span class="en-US">Previous generate time</span>
     * <span class="zh-CN">上次生成ID的时间</span>
     */
    private long lastTime = Globals.DEFAULT_VALUE_LONG;
    /**
	 * <h3 class="en-US">Configure current generator</h3>
	 * <h3 class="zh-CN">修改当前生成器的配置</h3>
     *
     * @param referenceTime     <span class="en-US">Reference time, default value: 1303315200000L</span>
     *                          <span class="zh-CN">起始时间戳，默认值：1303315200000L</span>
     * @param deviceId          <span class="en-US">Node device ID (between 0 and 63), default value: 1L</span>
     *                          <span class="zh-CN">节点的机器ID（取值范围：0到63），默认值：1L</span>
     * @param instanceId        <span class="en-US">Node instance ID (between 0 and 63), default value: 1L</span>
     *                          <span class="zh-CN">节点的实例ID（取值范围：0到63），默认值：1L</span>
     */
    public void config(final long referenceTime, final long deviceId, final long instanceId) {
        this.referenceTime = (referenceTime >= 0L) ? referenceTime : Globals.DEFAULT_REFERENCE_TIME;
        this.deviceId = (deviceId >= 0L && deviceId <= 64L) ? deviceId : DEFAULT_ID;
        this.instanceId = (instanceId >= 0L && instanceId <= 64L) ? instanceId : DEFAULT_ID;
        this.sequenceIndex = 0L;
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Config_Snowflake_Error",
                    this.referenceTime, this.deviceId, this.instanceId);
        }
    }
    /**
	 * <h3 class="en-US">Generate ID value</h3>
	 * <h3 class="zh-CN">生成ID值</h3>
     *
     * @return  <span class="en-US">Generated value</span>
     *          <span class="zh-CN">生成的ID值</span>
     */
    @Override
    public Long generate() {
        long currentTime = DateTimeUtils.currentUTCTimeMillis();
        if (currentTime < this.lastTime) {
            throw new RuntimeException(
                    String.format("System clock moved backwards. Refusing to generate id for %d milliseconds",
                            this.lastTime - currentTime));
        }

        if (currentTime == this.lastTime) {
            this.sequenceIndex = (this.sequenceIndex + 1) & SEQUENCE_MASK;
            if (this.sequenceIndex == 0) {
                while (true) {
                    if ((currentTime = DateTimeUtils.currentUTCTimeMillis()) > this.lastTime) {
                        break;
                    }
                }
            }
        } else {
            this.sequenceIndex = 0L;
        }
        this.lastTime = currentTime;

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Generate_Snowflake_Debug",
                    this.lastTime, this.referenceTime, this.deviceId, this.instanceId, this.sequenceIndex);
        }

        return ((this.lastTime - this.referenceTime) << 22L)
                | (this.deviceId << 17L) | (this.instanceId << 12L) | this.sequenceIndex;
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
    public Long generate(byte[] dataBytes) {
        return this.generate();
    }
    /**
	 * <h3 class="en-US">Destroy current generator instance</h3>
	 * <h3 class="zh-CN">销毁当前生成器实例对象</h3>
     */
    @Override
    public void destroy() {
    }
}
