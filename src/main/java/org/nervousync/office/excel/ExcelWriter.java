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

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;

/**
 * <h2 class="en-US">Excel file data writer interface</h2>
 * <h2 class="zh-CN">Excel文件数据写入器接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 14:25:10 $
 */
public interface ExcelWriter extends Closeable {

	/**
	 * <h3 class="en-US">Write data to disk</h3>
	 * <h3 class="zh-CN">将数据写入到磁盘</h3>
	 *
	 * @throws IOException <span class="en-US">An error occurred while writing data to disk</span>
	 *                     <span class="zh-CN">写入数据到磁盘时出错</span>
	 */
	void write() throws IOException;

	/**
	 * <h3 class="en-US">Write data to the given output stream</h3>
	 * <h3 class="zh-CN">将数据写入到给定的输出流中</h3>
	 *
	 * @param outputStream <span class="en-US">Data output stream instance object</span>
	 *                     <span class="zh-CN">数据输出流实例对象</span>
	 * @throws IOException <span class="en-US">An error occurred while writing data to the output stream</span>
	 *                     <span class="zh-CN">写入数据到输出流时出错</span>
	 */
	void write(final OutputStream outputStream) throws IOException;

	/**
	 * <h3 class="en-US">Get the sheet writer instance object of the given data table name</h3>
	 * <h3 class="zh-CN">获取给定数据表名的数据写入器实例对象</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @return <span class="en-US">Sheet writer instance object</span>
	 * <span class="zh-CN">数据写入器实例对象</span>
	 */
	SheetWriter sheetWriter(final String sheetName);

}
