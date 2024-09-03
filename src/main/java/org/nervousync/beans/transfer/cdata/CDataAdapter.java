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
package org.nervousync.beans.transfer.cdata;

import org.nervousync.beans.transfer.AbstractAdapter;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">CData adapter</h2>
 * <h2 class="zh-CN">CDATA数据转换器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $Date: Jun 15, 2020 14:09:27 $
 */
public final class CDataAdapter extends AbstractAdapter {

	/**
	 * <span class="en-US">Begin string of CDATA</span>
	 * <span class="zh-CN">CDATA起始字符串</span>
	 */
	public static final String CDATA_BEGIN = "<![CDATA[";
	/**
	 * <span class="en-US">End string of CDATA</span>
	 * <span class="zh-CN">CDATA终止字符串</span>
	 */
	public static final String CDATA_END = "]]>";

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#unmarshal(Object)
	 */
	@Override
	public Object unmarshal(final String v) {
		if (StringUtils.isEmpty(v)) {
			return "";
		}
		String dataValue = v;
		if (dataValue.startsWith(CDATA_BEGIN)) {
			dataValue = dataValue.substring(CDATA_BEGIN.length());
		}
		if (dataValue.endsWith(CDATA_END)) {
			dataValue = dataValue.substring(0, dataValue.length() - CDATA_END.length());
		}
		return dataValue;
	}

	/**
	 * @see jakarta.xml.bind.annotation.adapters.XmlAdapter#marshal(Object)
	 */
	@Override
	public String marshal(final Object v) {
		if (v instanceof String && StringUtils.notBlank((String) v)) {
			return CDATA_BEGIN + v + CDATA_END;
		}
		return CDATA_BEGIN + CDATA_END;
	}
}
