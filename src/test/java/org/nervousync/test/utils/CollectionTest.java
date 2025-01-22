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

package org.nervousync.test.utils;

import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.nervousync.test.BaseTest;
import org.nervousync.utils.CollectionUtils;

import java.util.List;
import java.util.Map;

public final class CollectionTest extends BaseTest {

	private static final List<Object> ARRAY_LIST = List.of("Test1", "Test2", "Test3", "Test4");
	private static final Object[] ARRAY_OBJECT = new Object[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
	private static final Map<?, ?> MAP_OBJECT = Map.of("Test1", 1, "Test2", 2, "Test3", 3, "Test4", 4);

	@Test
	@Order(10)
	public void checkEmpty() {
		this.logger.info("Collection_Is_Empty", "List", CollectionUtils.isEmpty(ARRAY_LIST));
		this.logger.info("Collection_Is_Empty", "Array", CollectionUtils.isEmpty(ARRAY_OBJECT));
		this.logger.info("Collection_Is_Empty", "Map", CollectionUtils.isEmpty(MAP_OBJECT));
	}

	@Test
	@Order(20)
	public void getLength() {
		this.logger.info("Collection_Length", "List", CollectionUtils.getLength(ARRAY_LIST));
		this.logger.info("Collection_Length", "Array", CollectionUtils.getLength(ARRAY_OBJECT));
		this.logger.info("Collection_Length", "Map", CollectionUtils.getLength(MAP_OBJECT));
	}
}
