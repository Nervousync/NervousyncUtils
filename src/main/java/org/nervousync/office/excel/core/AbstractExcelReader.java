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

package org.nervousync.office.excel.core;

import org.nervousync.commons.Globals;
import org.nervousync.office.excel.ExcelReader;
import org.nervousync.utils.CollectionUtils;
import org.nervousync.utils.LoggerUtils;

import java.util.*;

/**
 * <h2 class="en-US">Excel file reader abstract class</h2>
 * <h2 class="zh-CN">Excel文件读取器抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 12:06:15 $
 */
public abstract class AbstractExcelReader implements ExcelReader {

    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    protected transient final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
    /**
     * <span class="en-US">File storage path</span>
     * <span class="zh-CN">文件存储路径</span>
     */
    protected final String filePath;
    /**
     * <span class="en-US">List of data sheet names contained in the file</span>
     * <span class="zh-CN">文件中包含的数据表名列表</span>
     */
    protected final List<String> sheetNames;

    /**
     * <h3 class="en-US">Constructor method for excel reader</h3>
     * <h3 class="zh-CN">读取器构造方法</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     */
    protected AbstractExcelReader(final String filePath) {
        this.filePath = filePath;
        this.sheetNames = new ArrayList<>();
    }

    /**
     * <h3 class="en-US">Checks whether the given data sheet names exists</h3>
     * <h3 class="zh-CN">检查给定的数据表名是否存在</h3>
     *
     * @param sheetNames <span class="en-US">Data sheet names to check</span>
     *                   <span class="zh-CN">要检查的数据表名称</span>
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    @Override
    public final boolean checkExists(final String... sheetNames) {
        return CollectionUtils.containsAll(this.sheetNames, Arrays.asList(sheetNames));
    }

    /**
     * <h3 class="en-US">Get the maximum number of records in all data sheets</h3>
     * <h3 class="zh-CN">获取所有数据表的最大记录数</h3>
     *
     * @return <span class="en-US">Mapping table between data table name and maximum number of sheets</span>
     * <span class="zh-CN">数据表名与最大记录数的映射表</span>
     */
    @Override
    public final Map<String, Integer> maxRows() {
        final Map<String, Integer> dataMap = new HashMap<>();
        this.sheetNames.forEach(sheetName ->
                Optional.of(maxRow(sheetName))
                        .filter(rowCount -> rowCount != Globals.DEFAULT_VALUE_LONG)
                        .ifPresent(rowCount -> dataMap.put(sheetName, rowCount)));
        return dataMap;
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
    @Override
    public final Map<String, List<List<String>>> read(int beginRow, int endRow) {
        final Map<String, List<List<String>>> dataMap = new HashMap<>();
        this.sheetNames.forEach(sheetName ->
                Optional.of(read(sheetName, beginRow, endRow))
                        .filter(dataList -> !CollectionUtils.isEmpty(dataList))
                        .ifPresent(dataList -> dataMap.put(sheetName, dataList)));
        return dataMap;
    }
}
