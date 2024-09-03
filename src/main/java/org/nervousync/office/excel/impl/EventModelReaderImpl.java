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

import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.ss.usermodel.BuiltinFormats;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.eventusermodel.XSSFReader;
import org.apache.poi.xssf.model.SharedStrings;
import org.apache.poi.xssf.model.StylesTable;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFRichTextString;
import org.nervousync.commons.Globals;
import org.nervousync.office.excel.core.AbstractExcelReader;
import org.nervousync.utils.IOUtils;
import org.nervousync.utils.ObjectUtils;
import org.nervousync.utils.StringUtils;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParserFactory;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <h2 class="en-US">SAX event-driven Excel file reader</h2>
 * <h2 class="zh-CN">SAX事件驱动的Excel文件读取器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 10:45:33 $
 */
public final class EventModelReaderImpl extends AbstractExcelReader {

	/**
	 * <span class="en-US">Excel document package</span>
	 * <span class="zh-CN">Excel文档数据包</span>
	 */
	private final OPCPackage opcPackage;

	/**
	 * <h3 class="en-US">Constructor method for event model reader</h3>
	 * <h3 class="zh-CN">读取器构造方法</h3>
	 *
	 * @param filePath <span class="en-US">File storage path</span>
	 *                 <span class="zh-CN">文件存储路径</span>
	 * @throws InvalidFormatException <span class="en-US">If the file is not in XLSX format</span>
	 *                                <span class="zh-CN">如果文件不是XLSX格式</span>
	 */
	public EventModelReaderImpl(final String filePath) throws InvalidFormatException {
		super(filePath);
		this.opcPackage = OPCPackage.open(filePath, PackageAccess.READ);
		this.parseSheetNames();
	}

	/**
	 * <h3 class="en-US">Read the names of all data sheets in the current document</h3>
	 * <h3 class="zh-CN">读取当前文档中所有数据表的名称</h3>
	 */
	private void parseSheetNames() {
		try {
			XSSFReader xssfReader = new XSSFReader(this.opcPackage);
			XSSFReader.SheetIterator iterator = (XSSFReader.SheetIterator) xssfReader.getSheetsData();
			while (iterator.hasNext()) {
				try (InputStream ignored = iterator.next()) {
					this.sheetNames.add(iterator.getSheetName());
				}
			}
		} catch (Exception e) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Stack_Message_Error", e);
			}
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
		try {
			XSSFReader xssfReader = new XSSFReader(this.opcPackage);
			XMLReader xmlReader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
			MaxRowHandler maxRowHandler = new MaxRowHandler();
			xmlReader.setContentHandler(maxRowHandler);
			XSSFReader.SheetIterator iterator = (XSSFReader.SheetIterator) xssfReader.getSheetsData();
			while (iterator.hasNext()) {
				try (InputStream inputStream = iterator.next()) {
					if (ObjectUtils.nullSafeEquals(iterator.getSheetName(), sheetName)) {
						xmlReader.parse(new InputSource(inputStream));
						return maxRowHandler.getMaxRow();
					}
				}
			}
		} catch (Exception e) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Stack_Message_Error", e);
			}
		}
		return Globals.DEFAULT_VALUE_INT;
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
		InputStream inputStream = null;
		try {
			XSSFReader xssfReader = new XSSFReader(this.opcPackage);
			XMLReader xmlReader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
			SheetHandler sheetHandler =
					new SheetHandler(xssfReader.getStylesTable(), xssfReader.getSharedStringsTable(), beginRow, endRow);
			xmlReader.setContentHandler(sheetHandler);
			XSSFReader.SheetIterator iterator = (XSSFReader.SheetIterator) xssfReader.getSheetsData();
			while (iterator.hasNext()) {
				inputStream = iterator.next();
				if (ObjectUtils.nullSafeEquals(iterator.getSheetName(), sheetName)) {
					xmlReader.parse(new InputSource(inputStream));
					return sheetHandler.getDataList();
				}
			}
		} catch (Exception e) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Stack_Message_Error", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
		}
		return new ArrayList<>();
	}

	/**
	 * <h3 class="en-US">Close current data reader</h3>
	 * <h3 class="zh-CN">关闭当前数据读取器</h3>
	 */
	@Override
	public void close() {
		this.opcPackage.revert();
	}

	/**
	 * <h2 class="en-US">Data processor to read maximum number of rows</h2>
	 * <h2 class="zh-CN">读取最大行数的数据处理器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 10:53:16 $
	 */
	private static final class MaxRowHandler extends DefaultHandler {

		private int maxRow = Globals.INITIALIZE_INT_VALUE;

		@Override
		public void startElement(final String uri, final String localName, final String name,
		                         final Attributes attributes) {
			if ("c".equals(name)) {
				if (Pattern.compile("^A([0-9]+)$").matcher(attributes.getValue("r")).find()) {
					this.maxRow++;
				}
			}
		}

		public int getMaxRow() {
			return this.maxRow;
		}
	}

	/**
	 * <h2 class="en-US">Data processor to read detailed information</h2>
	 * <h2 class="zh-CN">读取详细信息的数据处理器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 10:59:28 $
	 */
	private static final class SheetHandler extends DefaultHandler {

		private final StylesTable stylesTable;
		private final SharedStrings sharedStrings;
		private final DataFormatter dataFormatter;
		private final int beginRow;
		private final int endRow;
		private String lastContents;
		private CellDataType dataType;
		private List<List<String>> dataList;
		private List<String> rowData = new ArrayList<>();
		private short formatIndex = Globals.DEFAULT_VALUE_SHORT;
		private String formatInfo = Globals.DEFAULT_VALUE_STRING;
		private int currentCol = Globals.INITIALIZE_INT_VALUE;
		private int currentRow = Globals.INITIALIZE_INT_VALUE;

		private SheetHandler(final StylesTable stylesTable, final SharedStrings sharedStrings,
		                     final int beginRow, final int endRow) {
			this.stylesTable = stylesTable;
			this.sharedStrings = sharedStrings;
			this.beginRow = beginRow;
			this.endRow = endRow;
			this.dataFormatter = new DataFormatter();
			this.resetDataList();
		}

		/**
		 * Reset data list.
		 */
		void resetDataList() {
			this.dataList = new ArrayList<>();
			this.currentCol = Globals.INITIALIZE_INT_VALUE;
			this.currentRow = Globals.INITIALIZE_INT_VALUE;
		}

		/**
		 * Gets the data list.
		 *
		 * @return the dataList
		 */
		public List<List<String>> getDataList() {
			return dataList;
		}

		private String parseRow(final String string) {
			Matcher matcher = Pattern.compile("\\d+").matcher(string);
			if (matcher.find()) {
				return matcher.group();
			}
			return Globals.DEFAULT_VALUE_STRING;
		}

		private String parseColumn(final String string) {
			Matcher matcher = Pattern.compile("[a-zA-Z]+").matcher(string);
			if (matcher.find()) {
				return matcher.group();
			}
			return Globals.DEFAULT_VALUE_STRING;
		}

		@Override
		public void startElement(final String uri, final String localName, final String name,
		                         final Attributes attributes) {
			if ((this.beginRow != Globals.DEFAULT_VALUE_INT && this.currentRow < this.beginRow)
					|| (this.endRow != Globals.DEFAULT_VALUE_INT && this.currentRow >= this.endRow)) {
				return;
			}

			if (name.equals("c") || name.equals("f")) {
				this.parseCellDataType(attributes);
				this.currentCol++;
			} else if (name.equalsIgnoreCase("mergeCell")) {
				String mergeRef = attributes.getValue("ref");
				String[] itemRef = StringUtils.tokenizeToStringArray(mergeRef, ":");
				int beginRow = Integer.parseInt(this.parseRow(itemRef[0])) - 1;
				int endRow = Integer.parseInt(this.parseRow(itemRef[1]));
				int beginColumn = CellReference.convertColStringToIndex(this.parseColumn(itemRef[0]));
				int endColumn = CellReference.convertColStringToIndex(this.parseColumn(itemRef[1]));
				String mergeData = this.dataList.get(beginRow).get(beginColumn);
				for (int i = beginRow; i < endRow; i++) {
					List<String> rowData = this.dataList.get(i);
					for (int j = beginColumn; j <= endColumn; j++) {
						if (rowData.size() <= j) {
							while (rowData.size() < j) {
								rowData.add(Globals.DEFAULT_VALUE_STRING);
							}
							rowData.add(mergeData);
						} else {
							rowData.set(j, mergeData);
						}
					}
					this.dataList.set(i, rowData);
				}
			}
			this.lastContents = "";
		}

		@Override
		public void endElement(final String uri, final String localName, final String name) {
			if ((this.beginRow != Globals.DEFAULT_VALUE_INT && this.currentRow < this.beginRow)
					|| (this.endRow != Globals.DEFAULT_VALUE_INT && this.currentRow >= this.endRow)) {
				if (name.equals("row")) {
					this.currentRow++;
					this.currentCol = Globals.INITIALIZE_INT_VALUE;
				}
				return;
			}

			switch (name) {
				case "v":
					XSSFRichTextString xssfRichTextString;
					switch (this.dataType) {
						case BOOLEAN:
							this.lastContents = (this.lastContents.charAt(0) == '0') ? "false" : "true";
							break;
						case ERROR:
							this.lastContents = "\"Error: " + this.lastContents + "\"";
							break;
						case INLINE_STRING:
							xssfRichTextString = new XSSFRichTextString(this.lastContents);
							this.lastContents = xssfRichTextString.toString();
							break;
						case SSTINDEX:
							try {
								int index = Integer.parseInt(this.lastContents);
								xssfRichTextString = (XSSFRichTextString) this.sharedStrings.getItemAt(index);
								this.lastContents = xssfRichTextString.toString();
							} catch (NumberFormatException ignored) {
							}
							break;
						case NUMBER:
							if (this.formatInfo != null) {
								this.lastContents =
										this.dataFormatter.formatRawCellContents(Double.parseDouble(this.lastContents),
												this.formatIndex, this.formatInfo);
							}
							break;
						default:
							break;
					}

					while ((this.currentCol - this.rowData.size()) > 1) {
						this.rowData.add(Globals.DEFAULT_VALUE_STRING);
					}
					this.rowData.add(this.currentCol - 1, this.lastContents);
					break;
				case "t":
					if (CellDataType.INLINE_STRING.equals(this.dataType)) {
						this.rowData.add(this.currentCol - 1, this.lastContents);
					}
					break;
				case "row":
					while (this.rowData.size() < this.currentCol) {
						this.rowData.add(Globals.DEFAULT_VALUE_STRING);
					}
					this.dataList.add(this.rowData);
					this.rowData = new ArrayList<>();
					this.currentRow++;
					this.currentCol = Globals.INITIALIZE_INT_VALUE;
			}
		}

		public void characters(final char[] ch, final int start, final int length) {
			if ((this.beginRow != Globals.DEFAULT_VALUE_INT && this.currentRow < this.beginRow)
					|| (this.endRow != Globals.DEFAULT_VALUE_INT && this.currentRow >= this.endRow)) {
				return;
			}
			this.lastContents += new String(ch, start, length);
		}

		private void parseCellDataType(final Attributes attributes) {
			String cellType = attributes.getValue("t");
			if (cellType == null) {
				cellType = Globals.DEFAULT_VALUE_STRING;
			}
			switch (cellType) {
				case "b":
					this.dataType = CellDataType.BOOLEAN;
					break;
				case "e":
					this.dataType = CellDataType.ERROR;
					break;
				case "inlineStr":
					this.dataType = CellDataType.INLINE_STRING;
					break;
				case "s":
					this.dataType = CellDataType.SSTINDEX;
					break;
				case "str":
					this.dataType = CellDataType.FORMULA;
					break;
				default:
					this.dataType = CellDataType.NUMBER;
					String cellStyle = attributes.getValue("s");

					if (cellStyle != null) {
						int styleIndex = Integer.parseInt(cellStyle);
						XSSFCellStyle xssfCellStyle = this.stylesTable.getStyleAt(styleIndex);
						this.formatIndex = xssfCellStyle.getDataFormat();
						this.formatInfo = xssfCellStyle.getDataFormatString();

						if (this.formatInfo == null) {
							this.formatInfo = BuiltinFormats.getBuiltinFormat(this.formatIndex);
						}
					}
					break;
			}
		}
	}

	private enum CellDataType {
		/**
		 * Boolean cell data type.
		 */
		BOOLEAN,
		/**
		 * Error cell data type.
		 */
		ERROR,
		/**
		 * Inline string cell data type.
		 */
		INLINE_STRING,
		/**
		 * Sstindex cell data type.
		 */
		SSTINDEX,
		/**
		 * Formula cell data type.
		 */
		FORMULA,
		/**
		 * Number cell data type.
		 */
		NUMBER
	}
}
