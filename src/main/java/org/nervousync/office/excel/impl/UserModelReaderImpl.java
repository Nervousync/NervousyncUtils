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

import org.apache.poi.ss.usermodel.*;
import org.nervousync.commons.Globals;
import org.nervousync.office.excel.core.AbstractExcelReader;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * <h2 class="en-US">Excel file reader for reading files in XLS format</h2>
 * <h2 class="zh-CN">Excel文件读取器，用于读取XLS格式的文件</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 11:06:21 $
 */
public final class UserModelReaderImpl extends AbstractExcelReader {

	/**
	 * <span class="en-US">Excel file input stream</span>
	 * <span class="zh-CN">Excel文件的输入流</span>
	 */
	private final InputStream inputStream;
	/**
	 * <span class="en-US">Excel document instance object</span>
	 * <span class="zh-CN">Excel文档实例对象</span>
	 */
	private final Workbook workbook;

	/**
	 * <h3 class="en-US">Constructor method for user model reader</h3>
	 * <h3 class="zh-CN">读取器构造方法</h3>
	 *
	 * @param filePath <span class="en-US">File storage path</span>
	 *                 <span class="zh-CN">文件存储路径</span>
	 * @throws IOException <span class="en-US">If the file does not exist or a reading error occurs</span>
	 *                     <span class="zh-CN">如果文件不存在或读取出错</span>
	 */
	public UserModelReaderImpl(final String filePath) throws IOException {
		super(filePath);
		this.inputStream = FileUtils.getURL(filePath).openStream();
		this.workbook = WorkbookFactory.create(this.inputStream);
		this.parseSheetNames();
	}

	/**
	 * <h3 class="en-US">Read the names of all data sheets in the current document</h3>
	 * <h3 class="zh-CN">读取当前文档中所有数据表的名称</h3>
	 */
	private void parseSheetNames() {
		for (int i = 0; i < this.workbook.getNumberOfSheets(); i++) {
			this.sheetNames.add(this.workbook.getSheetName(i));
		}
	}

	/**
	 * <h3 class="en-US">Get the maximum number of records based on the given data table name</h3>
	 * <h3 class="zh-CN">根据给定的数据表名称获取最大记录数</h3>
	 *
	 * @param sheetName <span class="en-US">Data sheet name</span>
	 *                  <span class="zh-CN">数据表名称</span>
	 * @return <span class="en-US">Maximum number of records read</span>
	 * <span class="zh-CN">读取的最大记录数</span>
	 */
	@Override
	public int maxRow(final String sheetName) {
		if (StringUtils.isEmpty(sheetName) || !this.sheetNames.contains(sheetName)) {
			return Globals.DEFAULT_VALUE_INT;
		}
		return Optional.ofNullable(this.workbook.getSheet(sheetName))
				.map(Sheet::getPhysicalNumberOfRows)
				.orElse(Globals.DEFAULT_VALUE_INT);
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
	@Override
	public List<List<String>> read(final String sheetName, final int beginRow, final int endRow) {
		if (StringUtils.isEmpty(sheetName) || !this.sheetNames.contains(sheetName)) {
			return new ArrayList<>();
		}
		List<List<String>> sheetList = new ArrayList<>();
		Sheet sheet = this.workbook.getSheet(sheetName);

		int beginIndex = Math.max(beginRow, Globals.INITIALIZE_INT_VALUE);
		int endIndex = Math.min(endRow, sheet.getPhysicalNumberOfRows());

		MergeData mergeData = new MergeData(sheet);
		if (sheet.getPhysicalNumberOfRows() > beginRow) {
			for (int i = beginIndex; i < endIndex; i++) {
				List<String> rowList = processRowData(mergeData, sheet.getRow(i));
				if (rowList == null) {
					continue;
				}
				sheetList.add(rowList);
			}
		}
		return sheetList;
	}

	/**
	 * <h3 class="en-US">Close current data reader</h3>
	 * <h3 class="zh-CN">关闭当前数据读取器</h3>
	 *
	 * @throws IOException <span class="en-US">If an exception occurs when closing the reader</span>
	 *                     <span class="zh-CN">如果关闭读取器时出现异常</span>
	 */
	@Override
	public void close() throws IOException {
		this.workbook.close();
		this.inputStream.close();
	}

	private static final class MergeData {

		private final List<MergeRegion> mergeRegionList = new ArrayList<>();

		public MergeData(final Sheet sheet) {
			sheet.getMergedRegions().forEach(cellAddress ->
					this.mergeRegionList.add(new MergeRegion(cellAddress.getFirstColumn(), cellAddress.getLastColumn(),
							cellAddress.getFirstRow(), cellAddress.getLastRow(),
							cellData(sheet.getRow(cellAddress.getFirstRow()).getCell(cellAddress.getFirstColumn())))));
		}

		public Optional<String> mergeData(final int column, final int row) {
			return this.mergeRegionList.stream()
					.filter(mergeRegion -> mergeRegion.contains(column, row))
					.findFirst()
					.map(MergeRegion::getCellData);
		}
	}

	private static final class MergeRegion {

		private final int beginColumn;
		private final int endColumn;
		private final int beginRow;
		private final int endRow;
		private final String cellData;

		public MergeRegion(final int beginColumn, final int endColumn, final int beginRow, final int endRow,
		                   final String cellData) {
			this.beginColumn = beginColumn;
			this.endColumn = endColumn;
			this.beginRow = beginRow;
			this.endRow = endRow;
			this.cellData = cellData;
		}

		public boolean contains(final int column, final int row) {
			return row >= this.beginRow && row <= this.endRow && column >= this.beginColumn && column <= this.endColumn;
		}

		public String getCellData() {
			return cellData;
		}
	}

	private static List<String> processRowData(final MergeData mergeData, final Row row) {
		if (row == null) {
			return null;
		}
		List<String> rowList = new ArrayList<>();

		for (int k = 0; k < row.getPhysicalNumberOfCells(); k++) {
			Cell cell = row.getCell(k);
			if (cell == null) {
				continue;
			}
			rowList.add(mergeData.mergeData(cell.getColumnIndex(), cell.getRowIndex())
					.orElseGet(() -> cellData(cell)));
		}

		return rowList;
	}

	private static String cellData(final Cell cell) {
		CellType cellType = cell.getCellType();
		switch (cellType) {
			case NUMERIC:
				double cellValue = cell.getNumericCellValue();
				String cellFormat = cell.getCellStyle().getDataFormatString();
				if (cellFormat.contains("#")) {
					return new BigDecimal(String.valueOf(cellValue)).stripTrailingZeros().toPlainString();
				} else {
					return DateTimeUtils.formatDate(cell.getDateCellValue(), DateTimeFormatter.ofPattern(cellFormat));
				}
			case BOOLEAN:
				return Boolean.toString(cell.getBooleanCellValue());
			case FORMULA:
				try {
					return new BigDecimal(String.valueOf(cell.getNumericCellValue())).stripTrailingZeros().toPlainString();
				} catch (IllegalStateException e) {
					return cell.getRichStringCellValue().toString();
				}
			case ERROR:
				return Globals.DEFAULT_VALUE_STRING;
			default:
				return cell.getStringCellValue();
		}
	}
}
