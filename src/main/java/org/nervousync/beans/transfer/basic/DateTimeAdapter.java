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
package org.nervousync.beans.transfer.basic;

import org.nervousync.beans.transfer.AbstractAdapter;
import org.nervousync.utils.DateTimeUtils;

import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * <h2 class="en-US">DateTime DataConverter</h2>
 * <h2 class="zh-CN">日期时间数据转换器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $Date: 2018-10-15 14:31
 */
public final class DateTimeAdapter extends AbstractAdapter {
	private final String pattern;

	public DateTimeAdapter() {
		this(DateTimeUtils.DEFAULT_DATETIME_PATTERN_ISO8601);
	}

	public DateTimeAdapter(final String pattern) {
		this.pattern = pattern;
	}

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#unmarshal(Object)
	 */
	@Override
	public Object unmarshal(final String v) {
		return DateTimeUtils.parseSiteMapDate(v);
	}

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#marshal(Object)
	 */
	@Override
	public String marshal(final Object v) {
		return DateTimeUtils.formatDate((Date) v, DateTimeFormatter.ofPattern(this.pattern));
	}
}
