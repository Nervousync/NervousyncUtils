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

import org.nervousync.commons.Globals;

import java.io.Closeable;
import java.util.List;
import java.util.Map;

/**
 * <h2 class="en-US">Excel file reader interface</h2>
 * <h2 class="zh-CN">Excel文件读取器接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 10:28:15 $
 */
public interface ExcelReader extends Closeable {

	/**
	 * <h3 class="en-US">Checks whether the given data sheet name exists</h3>
	 * <h3 class="zh-CN">检查给定的数据表名是否存在</h3>
	 *
	 * @param sheetNames <span class="en-US">Data sheet names to check</span>
	 *                   <span class="zh-CN">要检查的数据表名称</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	boolean checkExists(final String... sheetNames);

	/**
	 * <h3 class="en-US">Get the maximum number of records in all data sheets</h3>
	 * <h3 class="zh-CN">获取所有数据表的最大记录数</h3>
	 *
	 * @return <span class="en-US">Mapping table between data table name and maximum number of sheets</span>
	 * <span class="zh-CN">数据表名与最大记录数的映射表</span>
	 */
	Map<String, Integer> maxRows();

	/**
	 * <h3 class="en-US">Get the maximum number of records based on the given data sheet name</h3>
	 * <h3 class="zh-CN">根据给定的数据表名称获取最大记录数</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @return <span class="en-US">Maximum number of records read</span>
	 * <span class="zh-CN">读取的最大记录数</span>
	 */
	int maxRow(final String sheetName);

	/**
	 * <h3 class="en-US">Read all data in all data sheets</h3>
	 * <h3 class="zh-CN">读取所有数据表中的所有数据</h3>
	 *
	 * @return <span class="en-US">Mapping table of read data sheet name and data list</span>
	 * <span class="zh-CN">读取的数据表名和数据列表的映射表</span>
	 */
	default Map<String, List<List<String>>> read() {
		return this.read(Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Read data from all data sheets based on the given starting and ending row numbers</h3>
	 * <h3 class="zh-CN">根据给定的起始、终止行号读取所有数据表中的数据</h3>
	 *
	 * @param beginRow <span class="en-US">Begin row number</span>
	 *                 <span class="zh-CN">起始行号</span>
	 * @param endRow   <span class="en-US">End row number</span>
	 *                 <span class="zh-CN">终止行号</span>
	 * @return <span class="en-US">Mapping table of read data sheet name and data list</span>
	 * <span class="zh-CN">读取的数据表名和数据列表的映射表</span>
	 */
	Map<String, List<List<String>>> read(final int beginRow, final int endRow);

	/**
	 * <h3 class="en-US">Read all data based on the given data sheet name</h3>
	 * <h3 class="zh-CN">根据给定的数据表名称读取所有数据</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @return <span class="en-US">Read data list</span>
	 * <span class="zh-CN">读取的数据列表</span>
	 */
	default List<List<String>> read(final String sheetName) {
		return this.read(sheetName, Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Read data based on the given data sheet name, starting and ending row numbers</h3>
	 * <h3 class="zh-CN">根据给定的数据表名称和起始、终止行号读取数据</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @param beginRow  <span class="en-US">Begin row number</span>
	 *                  <span class="zh-CN">起始行号</span>
	 * @param endRow    <span class="en-US">End row number</span>
	 *                  <span class="zh-CN">终止行号</span>
	 * @return <span class="en-US">Read data list</span>
	 * <span class="zh-CN">读取的数据列表</span>
	 */
	List<List<String>> read(final String sheetName, final int beginRow, final int endRow);

}
