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

import jakarta.annotation.Nonnull;
import org.apache.poi.ss.usermodel.*;
import org.nervousync.commons.Globals;
import org.nervousync.office.excel.SheetWriter;

import java.util.Date;
import java.util.List;

/**
 * <h2 class="en-US">Sheet data writer implementation class</h2>
 * <h2 class="zh-CN">数据表数据写入器实现类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 14:10:05 $
 */
public final class SheetWriterImpl implements SheetWriter {

	/**
	 * <span class="en-US">Data sheet instance object</span>
	 * <span class="zh-CN">数据表实例对象</span>
	 */
	private final Sheet sheet;
	private final CellStyle dtStyle;
	private final CellStyle doubleStyle;

	/**
	 * <h3 class="en-US">Constructor method of data table data writer implementation class</h3>
	 * <h3 class="zh-CN">数据表数据写入器实现类的构造方法</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @param workbook  <span class="en-US">Excel workbook instance object</span>
	 *                  <span class="zh-CN">Excel工作簿实例对象</span>
	 */
	SheetWriterImpl(final String sheetName, @Nonnull final Workbook workbook) {
		Sheet sheet = workbook.getSheet(sheetName);
		if (sheet == null) {
			sheet = workbook.createSheet(sheetName);
		}
		this.sheet = sheet;
		this.dtStyle = workbook.createCellStyle();
		this.dtStyle.setDataFormat((short) 14);
		this.doubleStyle = workbook.createCellStyle();
		this.doubleStyle.setDataFormat(workbook.getCreationHelper().createDataFormat().getFormat("#,##0.00"));
	}

	/**
	 * <h3 class="en-US">Write the given data to the given line number</h3>
	 * <h3 class="zh-CN">写入给定数据到给定行号</h3>
	 *
	 * @param rowNum  <span class="en-US">Row number</span>
	 *                <span class="zh-CN">写入的行号</span>
	 * @param rowData <span class="en-US">Written data information</span>
	 *                <span class="zh-CN">写入的数据信息</span>
	 */
	@Override
	public void writeData(final int rowNum, final List<Object> rowData) {
		Row row;
		if (rowNum < this.sheet.getLastRowNum()) {
			row = this.sheet.getRow(rowNum);
		} else {
			row = this.sheet.createRow(rowNum);
		}
		for (int i = 0; i < rowData.size(); i++) {
			Cell cell;
			if (i < row.getLastCellNum()) {
				cell = row.getCell(i);
			} else {
				cell = row.createCell(i);
			}
			Object object = rowData.get(i);
			if (object != null) {
				if (object instanceof Date) {
					cell.setCellStyle(this.dtStyle);
					cell.setCellValue((Date) object);
				} else if (object instanceof Double) {
					cell.setCellStyle(this.doubleStyle);
					cell.setCellValue((double) object);
				} else if (object instanceof Boolean) {
					cell.setCellValue((boolean) object);
				} else {
					cell.setCellValue(object.toString());
				}
			} else {
				cell.setCellValue(Globals.DEFAULT_VALUE_STRING);
			}
		}
	}

	/**
	 * <h3 class="en-US">Write the given data to the end of the current data sheet</h3>
	 * <h3 class="zh-CN">写入给定数据到当前数据表末尾</h3>
	 *
	 * @param rowData <span class="en-US">Written data information</span>
	 *                <span class="zh-CN">写入的数据信息</span>
	 */
	@Override
	public void appendData(final List<Object> rowData) {
		this.writeData(this.sheet.getLastRowNum() + 1, rowData);
	}
}
