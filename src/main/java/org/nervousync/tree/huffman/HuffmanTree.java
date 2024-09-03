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
package org.nervousync.tree.huffman;

import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

import java.util.Hashtable;
import java.util.Optional;

/**
 * <h2 class="en-US">Huffman Tree</h2>
 * <h2 class="zh-CN">霍夫曼树</h2>
 * .0
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 3, 2017 16:39:41 $
 */
public final class HuffmanTree {
	/**
	 * <span class="en-US">Node counter</span>
	 * <span class="zh-CN">节点计数器</span>
	 */
	private int nodeCount = 0;
	/**
	 * <span class="en-US">Root node instance</span>
	 * <span class="zh-CN">根节点实例对象</span>
	 */
	private Node rootNode = null;
	/**
	 * <span class="en-US">Code mapping table</span>
	 * <span class="zh-CN">编码映射表</span>
	 */
	private Hashtable<String, Object> codeMapping = new Hashtable<>();

	/**
	 * <h3 class="en-US">Constructor method for HuffmanTree</h3>
	 * <h3 class="zh-CN">HuffmanTree构造方法</h3>
	 */
	public HuffmanTree() {
	}

	/**
	 * <h3 class="en-US">Private constructor method for HuffmanTree</h3>
	 * <h3 class="zh-CN">HuffmanTree私有构造方法</h3>
	 *
	 * @param codeMapping <span class="en-US">Code mapping table</span>
	 *                    <span class="zh-CN">编码映射表</span>
	 */
	private HuffmanTree(Hashtable<String, Object> codeMapping) {
		this.codeMapping = codeMapping;
	}

	/**
	 * <h3 class="en-US">Insert huffman node into current huffman tree</h3>
	 * <h3 class="zh-CN">插入一个霍夫曼节点到当前的霍夫曼树</h3>
	 *
	 * @param huffmanNode <span class="en-US">Huffman node who will insert into current huffman tree</span>
	 *                    <span class="zh-CN">即将插入当前霍夫曼树的霍夫曼节点</span>
	 */
	public void insertNode(final Node huffmanNode) {
		if (this.rootNode == null) {
			this.rootNode = huffmanNode;
		} else {
			Node currentNode = this.rootNode;
			Node previousNode = null;

			while (currentNode.getFrequency() < huffmanNode.getFrequency()) {
				previousNode = currentNode;
				if (currentNode.getNextNode() == null) {
					currentNode = null;
					break;
				} else {
					currentNode = currentNode.getNextNode();
				}
			}

			if (previousNode == null) {
				huffmanNode.setNextNode(this.rootNode);
				this.rootNode = huffmanNode;
			} else if (currentNode == null) {
				previousNode.setNextNode(huffmanNode);
			} else {
				previousNode.setNextNode(huffmanNode);
				huffmanNode.setNextNode(currentNode);
			}
		}
		this.nodeCount++;
	}

	/**
	 * <h3 class="en-US">Build code mapping table</h3>
	 * <h3 class="zh-CN">构建编码映射表</h3>
	 */
	public void build() {
		while (this.nodeCount > 1) {
			this.mergeNode();
		}
		this.buildCodeMapping(this.rootNode, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Static method for encode given content string to huffman tree result string using given code mapping</h3>
	 * <h3 class="zh-CN">静态方法，使用给定的编码映射表将给定的内容字符串编码为霍夫曼结果字符串</h3>
	 *
	 * @param codeMapping <span class="en-US">Code mapping table</span>
	 *                    <span class="zh-CN">编码映射表</span>
	 * @param content     <span class="en-US">Content string</span>
	 *                    <span class="zh-CN">内容字符串</span>
	 * @return <span class="en-US">Generated huffman result string or zero length string if content string is empty</span>
	 * <span class="zh-CN">生成的霍夫曼树编码字符串，当内容字符串为空字符串时返回长度为0的空字符串</span>
	 */
	public static String encodeString(final Hashtable<String, Object> codeMapping, String content) {
		HuffmanTree huffmanTree = new HuffmanTree(codeMapping);
		return Optional.ofNullable(huffmanTree.encodeString(content))
				.map(Result::getHuffmanValue)
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Encode given content string to huffman tree result instance using current code mapping</h3>
	 * <h3 class="zh-CN">使用当前的编码映射表将给定的内容字符串编码为霍夫曼结果实例对象</h3>
	 *
	 * @param content <span class="en-US">Content string</span>
	 *                <span class="zh-CN">内容字符串</span>
	 * @return <span class="en-US">Generated huffman result instance or null if content string is empty</span>
	 * <span class="zh-CN">生成的霍夫曼结果实例对象，当内容字符串为空字符串时返回null</span>
	 */
	public Result encodeString(final String content) {
		if (StringUtils.isEmpty(content)) {
			return null;
		}

		String string = content;
		StringBuilder stringBuilder = new StringBuilder();

		while (!string.isEmpty()) {
			String keyword = String.valueOf(string.charAt(0));
			stringBuilder.append(this.codeMapping.get(keyword));
			string = string.substring(1);
		}

		return new Result(this.codeMapping, stringBuilder.toString());
	}

	/**
	 * <h3 class="en-US">Build code mapping table</h3>
	 * <h3 class="zh-CN">构建编码映射表</h3>
	 *
	 * @param currentNode <span class="en-US">Current huffman node</span>
	 *                    <span class="zh-CN">当前霍夫曼节点</span>
	 * @param currentCode <span class="en-US">Code symbol</span>
	 *                    <span class="zh-CN">编码符号</span>
	 */
	private void buildCodeMapping(final Node currentNode, final String currentCode) {
		if (currentNode.getKeyword() != null) {
			this.codeMapping.put(currentNode.getKeyword(), currentCode);
		} else {
			this.buildCodeMapping(currentNode.getLeftNode(), currentCode + "0");
			this.buildCodeMapping(currentNode.getRightNode(), currentCode + "1");
		}
	}

	/**
	 * <h3 class="en-US">Merge huffman node which two frequency was lowest</h3>
	 * <h3 class="zh-CN">合并两个权重最低的节点，并将合并后的节点添加到霍夫曼树中</h3>
	 */
	private void mergeNode() {
		Node leftNode = this.pollNode();
		Node rightNode = this.pollNode();

		if (leftNode != null && rightNode != null) {
			Node mergeNode = new Node(leftNode.getFrequency() + rightNode.getFrequency());
			mergeNode.setLeftNode(leftNode);
			mergeNode.setRightNode(rightNode);
			this.insertNode(mergeNode);
		}
	}

	/**
	 * <h3 class="en-US">Retrieves and removes the head of this queue</h3>
	 * <h3 class="zh-CN">取出并移除当前队列的第一个节点</h3>
	 *
	 * @return <span class="en-US">Retrieved node or returns null if this queue is empty.</span>
	 * <span class="zh-CN">取出的节点，如果队列为空则返回null。</span>
	 */
	private Node pollNode() {
		if (this.rootNode == null) {
			return null;
		}
		Node removeNode = this.rootNode;
		this.rootNode = this.rootNode.getNextNode();
		this.nodeCount--;
		return removeNode;
	}

	/**
	 * <h2 class="en-US">Huffman Node</h2>
	 * <h2 class="zh-CN">霍夫曼节点</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Nov 3, 2017 16:26:45 $
	 */
	public static final class Node {
		/**
		 * <span class="en-US">Keyword</span>
		 * <span class="zh-CN">关键词</span>
		 */
		private String keyword;
		/**
		 * <span class="en-US">Frequency</span>
		 * <span class="zh-CN">权重</span>
		 */
		private int frequency;
		/**
		 * <span class="en-US">Left Node</span>
		 * <span class="zh-CN">左节点</span>
		 */
		private Node leftNode;
		/**
		 * <span class="en-US">Right Node</span>
		 * <span class="zh-CN">右节点</span>
		 */
		private Node rightNode;
		/**
		 * <span class="en-US">Next Node, using for chain table</span>
		 * <span class="zh-CN">下一节点，用于链表</span>
		 */
		private Node nextNode;

		/**
		 * <h3 class="en-US">Constructor method for HuffmanNode</h3>
		 * <h3 class="zh-CN">HuffmanNode构造方法</h3>
		 *
		 * @param frequency <span class="en-US">Frequency</span>
		 *                  <span class="zh-CN">权重</span>
		 */
		public Node(final int frequency) {
			this.frequency = frequency;
		}

		/**
		 * <h3 class="en-US">Constructor method for HuffmanNode</h3>
		 * <h3 class="zh-CN">HuffmanNode构造方法</h3>
		 *
		 * @param keyword   <span class="en-US">Keyword</span>
		 *                  <span class="zh-CN">关键词</span>
		 * @param frequency <span class="en-US">Frequency</span>
		 *                  <span class="zh-CN">权重</span>
		 */
		public Node(final String keyword, final int frequency) {
			this.keyword = keyword;
			this.frequency = frequency;
		}

		/**
		 * <h3 class="en-US">Getter method for keyword</h3>
		 * <h3 class="zh-CN">关键词的Getter方法</h3>
		 *
		 * @return <span class="en-US">Keyword</span>
		 * <span class="zh-CN">关键词</span>
		 */
		public String getKeyword() {
			return keyword;
		}

		/**
		 * <h3 class="en-US">Setter method for keyword</h3>
		 * <h3 class="zh-CN">关键词的Setter方法</h3>
		 *
		 * @param keyword <span class="en-US">Keyword</span>
		 *                <span class="zh-CN">关键词</span>
		 */
		public void setKeyword(final String keyword) {
			this.keyword = keyword;
		}

		/**
		 * <h3 class="en-US">Getter method for frequency</h3>
		 * <h3 class="zh-CN">权重的Getter方法</h3>
		 *
		 * @return <span class="en-US">Frequency</span>
		 * <span class="zh-CN">权重</span>
		 */
		public int getFrequency() {
			return frequency;
		}

		/**
		 * <h3 class="en-US">Setter method for frequency</h3>
		 * <h3 class="zh-CN">权重的Setter方法</h3>
		 *
		 * @param frequency <span class="en-US">Frequency</span>
		 *                  <span class="zh-CN">权重</span>
		 */
		public void setFrequency(final int frequency) {
			this.frequency = frequency;
		}

		/**
		 * <h3 class="en-US">Getter method for left node</h3>
		 * <h3 class="zh-CN">左节点的Getter方法</h3>
		 *
		 * @return <span class="en-US">Left Node</span>
		 * <span class="zh-CN">左节点</span>
		 */
		public Node getLeftNode() {
			return leftNode;
		}

		/**
		 * <h3 class="en-US">Setter method for left node</h3>
		 * <h3 class="zh-CN">左节点的Setter方法</h3>
		 *
		 * @param leftNode <span class="en-US">Left Node</span>
		 *                 <span class="zh-CN">左节点</span>
		 */
		public void setLeftNode(final Node leftNode) {
			this.leftNode = leftNode;
		}

		/**
		 * <h3 class="en-US">Getter method for right node</h3>
		 * <h3 class="zh-CN">右节点的Getter方法</h3>
		 *
		 * @return <span class="en-US">Right Node</span>
		 * <span class="zh-CN">右节点</span>
		 */
		public Node getRightNode() {
			return rightNode;
		}

		/**
		 * <h3 class="en-US">Setter method for right node</h3>
		 * <h3 class="zh-CN">右节点的Setter方法</h3>
		 *
		 * @param rightNode <span class="en-US">Right Node</span>
		 *                  <span class="zh-CN">右节点</span>
		 */
		public void setRightNode(final Node rightNode) {
			this.rightNode = rightNode;
		}

		/**
		 * <h3 class="en-US">Getter method for next node</h3>
		 * <h3 class="zh-CN">下一节点的Getter方法</h3>
		 *
		 * @return <span class="en-US">Next Node, using for chain table</span>
		 * <span class="zh-CN">下一节点，用于链表</span>
		 */
		public Node getNextNode() {
			return nextNode;
		}

		/**
		 * <h3 class="en-US">Setter method for next node</h3>
		 * <h3 class="zh-CN">下一节点的Setter方法</h3>
		 *
		 * @param nextNode <span class="en-US">Next Node, using for chain table</span>
		 *                 <span class="zh-CN">下一节点，用于链表</span>
		 */
		public void setNextNode(final Node nextNode) {
			this.nextNode = nextNode;
		}
	}

	/**
	 * <h2 class="en-US">Huffman Result</h2>
	 * <h2 class="zh-CN">霍夫曼编码结果</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Nov 6, 2017 14:13:35 $
	 */
	public static final class Result {
		/**
		 * <span class="en-US">Code mapping table</span>
		 * <span class="zh-CN">编码映射表</span>
		 */
		private final Hashtable<String, Object> codeMapping = new Hashtable<>();
		/**
		 * <span class="en-US">Result string</span>
		 * <span class="zh-CN">编码字符串</span>
		 */
		private final String huffmanValue;

		/**
		 * <h3 class="en-US">Constructor method for HuffmanResult</h3>
		 * <h3 class="zh-CN">HuffmanResult构造方法</h3>
		 *
		 * @param codeMapping  <span class="en-US">Code mapping table</span>
		 *                     <span class="zh-CN">编码映射表</span>
		 * @param huffmanValue <span class="en-US">Result string</span>
		 *                     <span class="zh-CN">编码字符串</span>
		 */
		public Result(final Hashtable<String, Object> codeMapping, final String huffmanValue) {
			if (codeMapping != null) {
				this.codeMapping.putAll(codeMapping);
			}
			this.huffmanValue = huffmanValue;
		}

		/**
		 * <h3 class="en-US">Convert coding map to JSON string</h3>
		 * <h3 class="zh-CN">转换编码映射表为JSON字符串</h3>
		 *
		 * @return <span class="en-US">Converted JSON string of current code mapping</span>
		 * <span class="zh-CN">当前编码映射表转换后的JSON字符串</span>
		 */
		public String codeMappingToString() {
			return StringUtils.objectToString(this.codeMapping, StringUtils.StringType.JSON, Boolean.TRUE);
		}

		/**
		 * <h3 class="en-US">Getter method for code mapping</h3>
		 * <h3 class="zh-CN">编码映射表的Getter方法</h3>
		 *
		 * @return <span class="en-US">Code mapping table</span>
		 * <span class="zh-CN">编码映射表</span>
		 */
		public Hashtable<String, Object> getCodeMapping() {
			return this.codeMapping;
		}

		/**
		 * <h3 class="en-US">Getter method for result string</h3>
		 * <h3 class="zh-CN">编码字符串的Getter方法</h3>
		 *
		 * @return <span class="en-US">Result string</span>
		 * <span class="zh-CN">编码字符串</span>
		 */
		public String getHuffmanValue() {
			return huffmanValue;
		}
	}
}
