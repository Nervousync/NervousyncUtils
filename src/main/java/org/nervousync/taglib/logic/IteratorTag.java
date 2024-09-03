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

package org.nervousync.taglib.logic;

import org.nervousync.commons.Globals;

public final class IteratorTag extends CollectionTag {

	@Override
	protected int startIndex() {
		return Globals.INITIALIZE_INT_VALUE;
	}

	@Override
	protected int endIndex() {
		return Globals.DEFAULT_VALUE_INT;
	}

	@Override
	protected int step() {
		return Globals.DEFAULT_STEP_VALUE;
	}
}
