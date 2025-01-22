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

package org.nervousync.office.excel.impl;

import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.office.excel.SheetWriter;
import org.nervousync.office.excel.core.AbstractExcelWriter;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.OfficeUtils;

import java.io.FileOutputStream;
import java.io.IOException;

/**
 * <h2 class="en-US">Excel file writer abstract class</h2>
 * <h2 class="zh-CN">Excel文件写入器抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 14:55:21 $
 */
public final class ExcelWriterImpl extends AbstractExcelWriter {

	/**
	 * <span class="en-US">File storage path</span>
	 * <span class="zh-CN">文件存储路径</span>
	 */
	private final String filePath;

	/**
	 * <h3 class="en-US">Constructor method for Excel writer</h3>
	 * <h3 class="zh-CN">写入器构造方法</h3>
	 *
	 * @param filePath <span class="en-US">File storage path</span>
	 *                 <span class="zh-CN">文件存储路径</span>
	 * @throws DataInvalidException <span class="en-US">If there is an error reading the file</span>
	 *                              <span class="zh-CN">如果读取文件出错</span>
	 */
	public ExcelWriterImpl(final String filePath) throws DataInvalidException {
		super(FileUtils.isExists(filePath) ? OfficeUtils.openWorkbook(filePath) : OfficeUtils.createWorkbook(filePath));
		this.filePath = filePath;
	}

	/**
	 * <h3 class="en-US">Write data to disk</h3>
	 * <h3 class="zh-CN">将数据写入到磁盘</h3>
	 *
	 * @throws IOException <span class="en-US">An error occurred while writing data to disk</span>
	 *                     <span class="zh-CN">写入数据到磁盘时出错</span>
	 */
	@Override
	public void write() throws IOException {
		try (FileOutputStream fileOutputStream = new FileOutputStream(this.filePath)) {
			this.write(fileOutputStream);
		} catch (Exception e) {
			this.logger.error("");
			if (this.logger.isDebugEnabled()) {
				this.logger.error("Stack_Message_Error", e);
			}
			throw new IOException(e);
		}
	}

	/**
	 * <h3 class="en-US">Get the sheet writer instance object of the given data table name</h3>
	 * <h3 class="zh-CN">获取给定数据表名的数据写入器实例对象</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @return <span class="en-US">Sheet writer instance object</span>
	 * <span class="zh-CN">数据写入器实例对象</span>
	 */
	@Override
	public SheetWriter sheetWriter(final String sheetName) {
		return new SheetWriterImpl(sheetName, this.workbook);
	}
}
