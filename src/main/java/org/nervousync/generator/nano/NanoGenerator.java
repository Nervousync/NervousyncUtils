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
package org.nervousync.generator.nano;

import org.nervousync.annotations.provider.Provider;
import org.nervousync.generator.IGenerator;
import org.nervousync.utils.IDUtils;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.StringUtils;

import java.security.SecureRandom;

/**
 * <h2 class="en-US">NanoID generator</h2>
 * <h2 class="zh-CN">NanoID生成器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:39:54 $
 */
@Provider(name = IDUtils.NANO_ID, titleKey = "nano.id.generator.name")
public final class NanoGenerator implements IGenerator<String> {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
    /**
     * <span class="en-US">Default alphabet string</span>
     * <span class="zh-CN">默认的字母表</span>
     */
    private static final String DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
    /**
     * <span class="en-US">Default length of generated result</span>
     * <span class="zh-CN">默认的生成结果长度</span>
     */
    private static final int DEFAULT_LENGTH = 27;
    /**
     * <span class="en-US">Secure Random instance</span>
     * <span class="zh-CN">安全随机数对象</span>
     */
    private final SecureRandom secureRandom = new SecureRandom();
    /**
     * <span class="en-US">Result used alphabet character array</span>
     * <span class="zh-CN">结果用到的字母字符数组</span>
     */
    private char[] alphabetArray = DEFAULT_ALPHABET.toCharArray();
    /**
     * <span class="en-US">Generated result length, default length: 27</span>
     * <span class="zh-CN">生成结果的长度，默认值：27</span>
     */
    private int generateLength = DEFAULT_LENGTH;
    /**
	 * <h3 class="en-US">Configure current generator</h3>
	 * <h3 class="zh-CN">修改当前生成器的配置</h3>
     *
     * @param alphabetConfig    <span class="en-US">Alphabet configure string</span>
     *                          <span class="zh-CN">输出字符设置</span>
     * @param generateLength    <span class="en-US">Generated result length</span>
     *                          <span class="zh-CN">生成结果的长度</span>
     */
    public void config(final String alphabetConfig, final int generateLength) {
        if (StringUtils.notBlank(alphabetConfig)) {
            if (alphabetConfig.length() > 255) {
                this.logger.error("Alphabet_Nano_Error");
            } else {
                this.alphabetArray = alphabetConfig.toCharArray();
            }
        }
        this.generateLength = generateLength > 0 ? generateLength : DEFAULT_LENGTH;
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
        final int mask = (2 << (int) Math.floor(Math.log(this.alphabetArray.length - 1) / Math.log(2))) - 1;
        final int length = (int) Math.ceil(1.6 * mask * this.generateLength / this.alphabetArray.length);

        final StringBuilder idBuilder = new StringBuilder();

        while (true) {
            final byte[] dataBytes = new byte[length];
            this.secureRandom.nextBytes(dataBytes);
            for (int i = 0; i < length; i++) {
                final int alphabetIndex = dataBytes[i] & mask;
                if (alphabetIndex < this.alphabetArray.length) {
                    idBuilder.append(this.alphabetArray[alphabetIndex]);
                    if (idBuilder.length() == this.generateLength) {
                        return idBuilder.toString();
                    }
                }
            }
        }
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
	 * <h3 class="en-US">Destroy current generator instance</h3>
	 * <h3 class="zh-CN">销毁当前生成器实例对象</h3>
     */
    @Override
    public void destroy() {
    }
}
