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
package org.nervousync.beans.transfer.beans;

import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

import java.util.Optional;

/**
 * <h2 class="en-US">JavaBean DataConverter</h2>
 * <h2 class="zh-CN">JavaBean数据转换器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jun 21, 2023 11:27:18 $
 */
public final class BeanObjectAdapter extends AbstractBeanAdapter {

	public BeanObjectAdapter(String className) throws IllegalArgumentException {
		super(className);
	}

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#unmarshal(Object)
	 */
	@Override
	public String marshal(final Object object) {
		return Optional.ofNullable(object)
				.map(Object::toString)
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#marshal(Object)
	 */
	@Override
	public Object unmarshal(final String string) {
		if (StringUtils.isEmpty(string)) {
			return null;
		}
		return StringUtils.stringToObject(string, this.beanClass);
	}
}
