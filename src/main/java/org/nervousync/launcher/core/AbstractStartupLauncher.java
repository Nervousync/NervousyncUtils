/*
 * Copyright 2022 Nervousync Studio
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.nervousync.launcher.core;

import org.nervousync.commons.core.Globals;
import org.nervousync.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractStartupLauncher {

	protected final Logger logger = LoggerFactory.getLogger(this.getClass());

	protected String parsePath(final String basePath) {
		if (StringUtils.isEmpty(basePath)) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		return basePath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)
				? basePath.substring(0, basePath.length() - 1)
				: basePath;
	}
}