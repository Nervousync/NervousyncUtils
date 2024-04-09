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

package org.nervousync.jmx;

import jakarta.annotation.Nonnull;
import org.nervousync.annotations.jmx.Monitor;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.StringUtils;

import javax.management.*;
import java.lang.management.ManagementFactory;
import java.util.Optional;

/**
 * <h2 class="en-US">JMX monitoring Bean interface, used for SPI to load monitoring objects</h2>
 * <h2 class="zh-CN">JMX监控Bean接口，用于SPI加载监控对象</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Feb 27, 2024 14:27:28 $
 */
public abstract class AbstractMBean {

	/**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	protected final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());

	protected AbstractMBean() {
		Optional.ofNullable(this.getClass().getAnnotation(Monitor.class))
				.map(this::objectName)
				.ifPresent(objectName -> {
					try {
						ManagementFactory.getPlatformMBeanServer().registerMBean(this, objectName);
					} catch (OperationsException | MBeanRegistrationException e) {
						this.logger.error("", e);
					}
				});
	}

	private ObjectName objectName(@Nonnull final Monitor monitor) {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(monitor.identify()).append(":").append("type=").append(monitor.type());
		if (StringUtils.notBlank(monitor.name())) {
			stringBuilder.append(",name=").append(monitor.name());
		}
		try {
			return new ObjectName(stringBuilder.toString());
		} catch (MalformedObjectNameException e) {
			this.logger.error("", e);
			return null;
		}
	}
}
