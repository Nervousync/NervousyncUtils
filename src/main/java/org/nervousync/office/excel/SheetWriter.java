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

package org.nervousync.office.excel;

import java.util.List;

/**
 * <h2 class="en-US">Sheet data writer interface</h2>
 * <h2 class="zh-CN">数据表数据写入器接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 14:10:05 $
 */
public interface SheetWriter {

	/**
	 * <h3 class="en-US">Write the given data to the given line number</h3>
	 * <h3 class="zh-CN">写入给定数据到给定行号</h3>
	 *
	 * @param rowNum  <span class="en-US">Row number</span>
	 *                <span class="zh-CN">写入的行号</span>
	 * @param rowData <span class="en-US">Written data information</span>
	 *                <span class="zh-CN">写入的数据信息</span>
	 */
	void writeData(final int rowNum, final List<Object> rowData);

	/**
	 * <h3 class="en-US">Write the given data to the end of the current data sheet</h3>
	 * <h3 class="zh-CN">写入给定数据到当前数据表末尾</h3>
	 *
	 * @param rowData <span class="en-US">Written data information</span>
	 *                <span class="zh-CN">写入的数据信息</span>
	 */
	void appendData(final List<Object> rowData);
}
