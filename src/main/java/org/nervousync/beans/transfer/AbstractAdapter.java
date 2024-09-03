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
package org.nervousync.beans.transfer;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import org.nervousync.utils.CollectionUtils;

import java.util.List;

/**
 * <h2 class="en-US">Abstract adapter for implements IConverter</h2>
 * <span class="en-US">Extend class XmlAdapter for compatible JAXB data converter</span>
 * <h2 class="zh-CN">实现接口IConverter的抽象转换器</h2>
 * <span class="zh-CN">继承类XmlAdapter，用于兼容JAXB数据转换器</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $ $Date: Jun 21, 2023 10:25:22 $
 */
public abstract class AbstractAdapter extends XmlAdapter<String, Object> {

	protected final byte[] toByteArray(final Object object) {
		List<?> convertList = CollectionUtils.toList(object);
		byte[] dataBytes = new byte[convertList.size()];
		for (int i = 0; i < convertList.size(); i++) {
			Object obj = convertList.get(i);
			if (obj instanceof Byte) {
				dataBytes[i] = (Byte) obj;
			}
		}
		return dataBytes;
	}
}
