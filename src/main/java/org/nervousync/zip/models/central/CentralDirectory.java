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
package org.nervousync.zip.models.central;

import java.util.ArrayList;
import java.util.List;

import org.nervousync.commons.Globals;
import org.nervousync.zip.models.header.GeneralFileHeader;
import org.nervousync.utils.FileUtils;

/**
 * The type Central directory.
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 28, 2017 4:52:40 PM $
 */
public final class CentralDirectory {

	private List<GeneralFileHeader> fileHeaders = null;
	private DigitalSignature digitalSignature = null;

	/**
	 * Instantiates a new Central directory.
	 */
	public CentralDirectory() {
	}

	/**
	 * Gets file headers.
	 *
	 * @return the fileHeaders
	 */
	public List<GeneralFileHeader> getFileHeaders() {
		return fileHeaders;
	}

	/**
	 * Sets file headers.
	 *
	 * @param fileHeaders the fileHeaders to set
	 */
	public void setFileHeaders(List<GeneralFileHeader> fileHeaders) {
		this.fileHeaders = fileHeaders;
	}

	/**
	 * Gets digital signature.
	 *
	 * @return the digitalSignature
	 */
	public DigitalSignature getDigitalSignature() {
		return digitalSignature;
	}

	/**
	 * Sets digital signature.
	 *
	 * @param digitalSignature the digitalSignature to set
	 */
	public void setDigitalSignature(DigitalSignature digitalSignature) {
		this.digitalSignature = digitalSignature;
	}

	/**
	 * List folder general file headers list.
	 *
	 * @param folderPath the folder path
	 * @return the list
	 */
	public List<String> listFolderGeneralFileHeaders(String folderPath) {
		List<String> headerList = new ArrayList<>();
		GeneralFileHeader folderFileHeader = this.retrieveGeneralFileHeader(folderPath);
		if (folderFileHeader != null && folderFileHeader.isDirectory()) {
			for (GeneralFileHeader generalFileHeader : this.fileHeaders) {
				if (FileUtils.matchFolder(generalFileHeader.getEntryPath(), folderPath)) {
					if (generalFileHeader.isDirectory()) {
						headerList.addAll(this.listFolderGeneralFileHeaders(generalFileHeader.getEntryPath()));
					} else {
						headerList.add(generalFileHeader.getEntryPath());
					}
				}
			}
			headerList.add(folderFileHeader.getEntryPath());
		}
		return headerList;
	}

	/**
	 * Retrieve general file header general file header.
	 *
	 * @param entryPath the entry path
	 * @return the general file header
	 */
	public GeneralFileHeader retrieveGeneralFileHeader(String entryPath) {
		if (this.fileHeaders != null && !this.fileHeaders.isEmpty()) {
			for (GeneralFileHeader generalFileHeader : this.fileHeaders) {
				if (FileUtils.matchFilePath(generalFileHeader.getEntryPath(), entryPath, true)) {
					return generalFileHeader;
				}
			}
		}
		return null;
	}

	/**
	 * Retrieve index of general file header int.
	 *
	 * @param generalFileHeader the general file header
	 * @return the int
	 */
	public int retrieveIndexOfGeneralFileHeader(GeneralFileHeader generalFileHeader) {
		if (this.fileHeaders != null && !this.fileHeaders.isEmpty()) {
			for (int index = 0; index < this.fileHeaders.size(); index++) {
				if (FileUtils.matchFilePath(generalFileHeader.getEntryPath(),
						this.fileHeaders.get(index).getEntryPath(), true)) {
					return index;
				}
			}
		}
		return Globals.DEFAULT_VALUE_INT;
	}
}
