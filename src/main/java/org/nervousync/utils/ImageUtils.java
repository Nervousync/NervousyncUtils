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
package org.nervousync.utils;

import jakarta.annotation.Nonnull;
import org.nervousync.beans.image.CutOptions;
import org.nervousync.beans.image.MarkOptions;
import org.nervousync.commons.Globals;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Optional;

/**
 * <h2 class="en-US">Image Utilities</h2>
 * <h2 class="zh-CN">图片工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: May 1, 2018 13:49:46 $
 */
public final class ImageUtils {
	/**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ImageUtils.class);

	/**
	 * <h3 class="en-US">Private constructor for ImageUtils</h3>
	 * <h3 class="zh-CN">图片工具集的私有构造方法</h3>
	 */
	private ImageUtils() {
	}

	/**
	 * <h3 class="en-US">Retrieve image width value</h3>
	 * <h3 class="zh-CN">获取图片宽度</h3>
	 *
	 * @param imagePath <span class="en-US">Image file path</span>
	 *                  <span class="zh-CN">图片地址</span>
	 * @return <span class="en-US">Image width value</span>
	 * <span class="zh-CN">图片宽度值</span>
	 */
	public static int imageWidth(final String imagePath) {
		if (FileUtils.isExists(imagePath) && FileUtils.imageFile(imagePath)) {
			try {
				BufferedImage srcImage = ImageIO.read(FileUtils.getFile(imagePath));
				return srcImage.getWidth(null);
			} catch (Exception e) {
				LOGGER.error("Read_Image_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return Globals.DEFAULT_VALUE_INT;
	}

	/**
	 * <h3 class="en-US">Retrieve image height value</h3>
	 * <h3 class="zh-CN">获取图片高度</h3>
	 *
	 * @param imagePath <span class="en-US">Image file path</span>
	 *                  <span class="zh-CN">图片地址</span>
	 * @return <span class="en-US">Image height value</span>
	 * <span class="zh-CN">图片高度值</span>
	 */
	public static int imageHeight(final String imagePath) {
		if (FileUtils.isExists(imagePath) && FileUtils.imageFile(imagePath)) {
			try {
				BufferedImage srcImage = ImageIO.read(FileUtils.getFile(imagePath));
				return srcImage.getHeight(null);
			} catch (Exception e) {
				LOGGER.error("Read_Image_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return Globals.DEFAULT_VALUE_INT;
	}

	/**
	 * <h3 class="en-US">Retrieve image ratio value</h3>
	 * <h3 class="zh-CN">获取图片宽高比</h3>
	 *
	 * @param imagePath <span class="en-US">Image file path</span>
	 *                  <span class="zh-CN">图片地址</span>
	 * @return <span class="en-US">Image ratio value</span>
	 * <span class="zh-CN">图片宽高比</span>
	 */
	public static double imageRatio(final String imagePath) {
		double imageHeight = ImageUtils.imageHeight(imagePath);
		double imageWidth = ImageUtils.imageHeight(imagePath);

		if (imageHeight == Globals.DEFAULT_VALUE_DOUBLE || imageWidth == Globals.DEFAULT_VALUE_DOUBLE) {
			return Globals.DEFAULT_VALUE_DOUBLE;
		}

		return imageWidth / imageHeight;
	}

	/**
	 * <h3 class="en-US">Cut original image file and save to target path by given cut options</h3>
	 * <h3 class="zh-CN">根据给定的切割参数对原始图片进行切割并存储到目标地址</h3>
	 *
	 * @param origPath   <span class="en-US">original image file path</span>
	 *                   <span class="zh-CN">原始图片地址</span>
	 * @param targetPath <span class="en-US">target image file path</span>
	 *                   <span class="zh-CN">目标图片地址</span>
	 * @param cutOptions <span class="en-US">cut options</span>
	 *                   <span class="zh-CN">切割参数</span>
	 * @return <span class="en-US">Cut process result</span>
	 * <span class="zh-CN">切割处理结果</span>
	 */
	public static boolean cutImage(final String origPath, final String targetPath, final CutOptions cutOptions) {
		if (origPath != null && FileUtils.isExists(origPath) && cutOptions != null) {
			if (cutOptions.getPositionX() + cutOptions.getCutWidth() > ImageUtils.imageWidth(origPath)) {
				LOGGER.error("Width_Exceeds_Original_Image_Error");
				return Boolean.FALSE;
			}
			if (cutOptions.getPositionY() + cutOptions.getCutHeight() > ImageUtils.imageHeight(origPath)) {
				LOGGER.error("Height_Exceeds_Original_Image_Error");
				return Boolean.FALSE;
			}

			try {
				BufferedImage srcImage = ImageIO.read(FileUtils.getFile(origPath));
				BufferedImage bufferedImage =
						new BufferedImage(cutOptions.getCutWidth(), cutOptions.getCutHeight(),
								BufferedImage.TYPE_INT_RGB);

				for (int i = 0; i < cutOptions.getCutWidth(); i++) {
					for (int j = 0; j < cutOptions.getCutHeight(); j++) {
						bufferedImage.setRGB(i, j,
								srcImage.getRGB(cutOptions.getPositionX() + i, cutOptions.getPositionY() + j));
					}
				}

				return ImageIO.write(bufferedImage, StringUtils.getFilenameExtension(targetPath),
						FileUtils.getFile(targetPath));
			} catch (Exception e) {
				LOGGER.error("Cut_Image_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Resize original image file and save to target path by given ratio value</h3>
	 * <h3 class="zh-CN">根据给定的缩放比例对原始图片进行放大/缩小并存储到目标地址</h3>
	 *
	 * @param origPath   <span class="en-US">original image file path</span>
	 *                   <span class="zh-CN">原始图片地址</span>
	 * @param targetPath <span class="en-US">target image file path</span>
	 *                   <span class="zh-CN">目标图片地址</span>
	 * @param ratio      <span class="en-US">ratio value</span>
	 *                   <span class="zh-CN">缩放比例</span>
	 * @return <span class="en-US">Resize process result</span>
	 * <span class="zh-CN">修改尺寸处理结果</span>
	 */
	public static boolean resizeByRatio(final String origPath, final String targetPath, final double ratio) {
		return ImageUtils.resizeByRatio(origPath, targetPath, ratio, null);
	}

	/**
	 * <h3 class="en-US">Resize original image file and save to target path by given ratio value, and add mark to target image if configured</h3>
	 * <h3 class="zh-CN">根据给定的缩放比例对原始图片进行放大/缩小并存储到目标地址，并添加水印到目标图片（如果设置了水印选项）</h3>
	 *
	 * @param origPath    <span class="en-US">original image file path</span>
	 *                    <span class="zh-CN">原始图片地址</span>
	 * @param targetPath  <span class="en-US">target image file path</span>
	 *                    <span class="zh-CN">目标图片地址</span>
	 * @param ratio       <span class="en-US">ratio value</span>
	 *                    <span class="zh-CN">缩放比例</span>
	 * @param markOptions <span class="en-US">Mark options</span>
	 *                    <span class="zh-CN">水印选项</span>
	 * @return <span class="en-US">Resize process result</span>
	 * <span class="zh-CN">修改尺寸处理结果</span>
	 */
	public static boolean resizeByRatio(final String origPath, final String targetPath, final double ratio,
	                                    final MarkOptions markOptions) {
		if (FileUtils.isExists(origPath) && FileUtils.imageFile(origPath) && ratio > 0) {
			try {
				BufferedImage srcImage = ImageIO.read(FileUtils.getFile(origPath));

				int origWidth = srcImage.getWidth(null);
				int origHeight = srcImage.getHeight(null);

				int targetWidth = Double.valueOf(origWidth * ratio).intValue();
				int targetHeight = Double.valueOf(origHeight * ratio).intValue();

				return ImageIO.write(processImage(srcImage, targetWidth, targetHeight, markOptions),
						StringUtils.getFilenameExtension(targetPath),
						FileUtils.getFile(targetPath));
			} catch (Exception e) {
				LOGGER.error("Resize_Image_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Resize original image file to the given width and height, save to target path</h3>
	 * <h3 class="zh-CN">将原始图片调整到指定的宽度、高度，并存储到目标地址</h3>
	 *
	 * @param origPath     <span class="en-US">original image file path</span>
	 *                     <span class="zh-CN">原始图片地址</span>
	 * @param targetPath   <span class="en-US">target image file path</span>
	 *                     <span class="zh-CN">目标图片地址</span>
	 * @param targetWidth  <span class="en-US">target width	(if -1 width will auto set by height ratio)</span>
	 *                     <span class="zh-CN">图片调整后的宽度，如果值为-1则自动根据图片宽高比进行调整</span>
	 * @param targetHeight <span class="en-US">target height	(if -1 height will auto set by width ratio)</span>
	 *                     <span class="zh-CN">图片调整后的高度，如果值为-1则自动根据图片宽高比进行调整</span>
	 * @return <span class="en-US">Resize process result</span>
	 * <span class="zh-CN">修改尺寸处理结果</span>
	 */
	public static boolean resizeTo(final String origPath, final String targetPath,
	                               final int targetWidth, final int targetHeight) {
		return ImageUtils.resizeTo(origPath, targetPath, targetWidth, targetHeight, null);
	}

	/**
	 * <h3 class="en-US">Resize original image file to the given width and height, save to target path, and add mark to target image if configured</h3>
	 * <h3 class="zh-CN">将原始图片调整到指定的宽度、高度，并存储到目标地址，并添加水印到目标图片（如果设置了水印选项）</h3>
	 *
	 * @param origPath     <span class="en-US">original image file path</span>
	 *                     <span class="zh-CN">原始图片地址</span>
	 * @param targetPath   <span class="en-US">target image file path</span>
	 *                     <span class="zh-CN">目标图片地址</span>
	 * @param targetWidth  <span class="en-US">target width	(if -1 width will auto set by height ratio)</span>
	 *                     <span class="zh-CN">图片调整后的宽度，如果值为-1则自动根据图片宽高比进行调整</span>
	 * @param targetHeight <span class="en-US">target height	(if -1 height will auto set by width ratio)</span>
	 *                     <span class="zh-CN">图片调整后的高度，如果值为-1则自动根据图片宽高比进行调整</span>
	 * @param markOptions  <span class="en-US">Mark options</span>
	 *                     <span class="zh-CN">水印选项</span>
	 * @return <span class="en-US">Resize process result</span>
	 * <span class="zh-CN">修改尺寸处理结果</span>
	 */
	public static boolean resizeTo(final String origPath, final String targetPath,
	                               final int targetWidth, final int targetHeight, final MarkOptions markOptions) {
		if (FileUtils.isExists(origPath) && FileUtils.imageFile(origPath)
				&& (targetWidth > 0 || targetHeight > 0)) {
			try {
				BufferedImage srcImage = ImageIO.read(FileUtils.getFile(origPath));

				int origWidth = srcImage.getWidth(null);
				int origHeight = srcImage.getHeight(null);

				int resizeWidth;
				if (targetWidth == Globals.DEFAULT_VALUE_INT) {
					double ratio = targetHeight * 1.0 / origHeight;
					resizeWidth = Double.valueOf(ratio * origWidth).intValue();
				} else {
					resizeWidth = targetWidth;
				}

				int resizeHeight;
				if (targetHeight == Globals.DEFAULT_VALUE_INT) {
					double ratio = targetWidth * 1.0 / origWidth;
					resizeHeight = Double.valueOf(ratio * origHeight).intValue();
				} else {
					resizeHeight = targetHeight;
				}

				return ImageIO.write(processImage(srcImage, resizeWidth, resizeHeight, markOptions),
						StringUtils.getFilenameExtension(targetPath), FileUtils.getFile(targetPath));
			} catch (Exception e) {
				LOGGER.error("Resize_Image_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Add mark to original image and save result image to target path</h3>
	 * <h3 class="zh-CN">添加水印到原始图片，并将添加好水印的图片保存到目标地址</h3>
	 *
	 * @param origPath    <span class="en-US">original image file path</span>
	 *                    <span class="zh-CN">原始图片地址</span>
	 * @param targetPath  <span class="en-US">target image file path</span>
	 *                    <span class="zh-CN">目标图片地址</span>
	 * @param markOptions <span class="en-US">Mark options</span>
	 *                    <span class="zh-CN">水印选项</span>
	 * @return <span class="en-US">Mark process result</span>
	 * <span class="zh-CN">添加水印处理结果</span>
	 */
	public static boolean markImage(final String origPath, final String targetPath, final MarkOptions markOptions) {
		int imageWidth = ImageUtils.imageWidth(origPath);
		int imageHeight = ImageUtils.imageHeight(origPath);
		try {
			BufferedImage bufferedImage = new BufferedImage(imageWidth, imageHeight, BufferedImage.TYPE_INT_RGB);
			return ImageIO.write(processImage(bufferedImage, imageWidth, imageHeight, markOptions),
					StringUtils.getFilenameExtension(targetPath),
					FileUtils.getFile(targetPath));
		} catch (Exception e) {
			LOGGER.error("Water_Mark_Image_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Add mark to buffered image</h3>
	 * <h3 class="zh-CN">添加水印到目标缓冲图片实例对象</h3>
	 *
	 * @param bufferedImage <span class="en-US">Buffered image</span>
	 *                      <span class="zh-CN">缓冲图片实例对象</span>
	 * @param markOptions   <span class="en-US">Mark options</span>
	 *                      <span class="zh-CN">水印选项</span>
	 */
	public static void markImage(@Nonnull final BufferedImage bufferedImage, final MarkOptions markOptions) {
		Graphics2D graphics = bufferedImage.createGraphics();
		markImage(graphics, bufferedImage.getWidth(), bufferedImage.getHeight(), markOptions);
		graphics.dispose();
	}

	/**
	 * <h3 class="en-US">Calculate dHash hamming between original image and target image</h3>
	 * <h3 class="en-US">计算原始图片和目标图片间差异值哈希的汉明距离</h3>
	 *
	 * @param origPath   <span class="en-US">original image file path</span>
	 *                   <span class="zh-CN">原始图片地址</span>
	 * @param targetPath <span class="en-US">target image file path</span>
	 *                   <span class="zh-CN">目标图片地址</span>
	 * @return <span class="en-US">Calculated hamming result</span>
	 * <span class="zh-CN">计算的汉明距离</span>
	 */
	public static int dHashHamming(final String origPath, final String targetPath) {
		String origHash = ImageUtils.dHash(origPath);
		String destHash = ImageUtils.dHash(targetPath);
		int diff = 0;
		for (int j = 0; j < origHash.length(); j++) {
			diff += (origHash.charAt(j) ^ destHash.charAt(j));
		}
		return diff;
	}

	/**
	 * <h3 class="en-US">Calculate pHash hamming between original image and target image</h3>
	 * <h3 class="en-US">计算原始图片和目标图片间感知哈希的汉明距离</h3>
	 *
	 * @param origPath   <span class="en-US">original image file path</span>
	 *                   <span class="zh-CN">原始图片地址</span>
	 * @param targetPath <span class="en-US">target image file path</span>
	 *                   <span class="zh-CN">目标图片地址</span>
	 * @return <span class="en-US">Calculated hamming result</span>
	 * <span class="zh-CN">计算的汉明距离</span>
	 */
	public static int pHashHamming(final String origPath, final String targetPath) {
		String origHash = ImageUtils.pHash(origPath);
		String destHash = ImageUtils.pHash(targetPath);
		int diff = 0;
		for (int j = 0; j < origHash.length(); j++) {
			diff += (origHash.charAt(j) ^ destHash.charAt(j));
		}
		return diff;
	}

	/**
	 * <h3 class="en-US">Calculate dHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的差异值哈希</h3>
	 *
	 * @param filePath <span class="en-US">Image file path</span>
	 *                 <span class="zh-CN">图片文件地址</span>
	 * @return <span class="en-US">dHash string</span>
	 * <span class="zh-CN">差异值哈希字符串</span>
	 */
	public static String dHash(final String filePath) {
		try {
			return ImageUtils.dHash(FileUtils.getFile(filePath));
		} catch (FileNotFoundException e) {
			LOGGER.error("Not_Found_File_Error", filePath);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_STRING;
		}
	}

	/**
	 * <h3 class="en-US">Calculate dHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的差异值哈希</h3>
	 *
	 * @param file <span class="en-US">Image file instance</span>
	 *             <span class="zh-CN">图片文件实例对象</span>
	 * @return <span class="en-US">dHash string</span>
	 * <span class="zh-CN">差异值哈希字符串</span>
	 */
	public static String dHash(final File file) {
		try {
			return ImageUtils.dHash(ImageIO.read(file));
		} catch (IOException e) {
			LOGGER.error("Read_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_STRING;
		}
	}

	/**
	 * <h3 class="en-US">Calculate dHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的差异值哈希</h3>
	 *
	 * @param bufferedImage <span class="en-US">Buffered image</span>
	 *                      <span class="zh-CN">缓冲图片实例对象</span>
	 * @return <span class="en-US">dHash string</span>
	 * <span class="zh-CN">差异值哈希字符串</span>
	 */
	public static String dHash(final BufferedImage bufferedImage) {
		BufferedImage prepareImage;
		if (bufferedImage.getWidth() != 9 || bufferedImage.getHeight() != 8) {
			prepareImage = ImageUtils.processImage(bufferedImage, 9, 8, null);
		} else {
			prepareImage = bufferedImage;
		}

		double[][] grayMatrix = ImageUtils.grayMatrix(prepareImage);
		StringBuilder dHash = new StringBuilder();
		for (int x = 0; x < 8; x++) {
			for (int y = 0; y < 8; y++) {
				dHash.append((grayMatrix[x][y] > grayMatrix[x][y + 1]) ? "1" : "0");
			}
		}
		return dHash.toString();
	}

	/**
	 * <h3 class="en-US">Calculate pHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的感知哈希</h3>
	 *
	 * @param filePath <span class="en-US">Image file path</span>
	 *                 <span class="zh-CN">图片文件地址</span>
	 * @return <span class="en-US">pHash string</span>
	 * <span class="zh-CN">感知哈希字符串</span>
	 */
	public static String pHash(final String filePath) {
		try {
			return ImageUtils.pHash(FileUtils.getFile(filePath));
		} catch (FileNotFoundException e) {
			LOGGER.error("Not_Found_File_Error", filePath);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_STRING;
		}
	}

	/**
	 * <h3 class="en-US">Calculate pHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的感知哈希</h3>
	 *
	 * @param file <span class="en-US">Image file instance</span>
	 *             <span class="zh-CN">图片文件实例对象</span>
	 * @return <span class="en-US">pHash string</span>
	 * <span class="zh-CN">感知哈希字符串</span>
	 */
	public static String pHash(final File file) {
		try {
			return ImageUtils.pHash(ImageIO.read(file));
		} catch (IOException e) {
			LOGGER.error("Read_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_STRING;
		}
	}

	/**
	 * <h3 class="en-US">Calculate pHash of given image file</h3>
	 * <h3 class="en-US">计算给定图片的感知哈希</h3>
	 *
	 * @param bufferedImage <span class="en-US">Buffered image</span>
	 *                      <span class="zh-CN">缓冲图片实例对象</span>
	 * @return <span class="en-US">pHash string</span>
	 * <span class="zh-CN">感知哈希字符串</span>
	 */
	public static String pHash(final BufferedImage bufferedImage) {
		BufferedImage prepareImage;
		if (bufferedImage.getWidth() != 8 || bufferedImage.getHeight() != 8) {
			prepareImage = ImageUtils.processImage(bufferedImage, 8, 8, null);
		} else {
			prepareImage = bufferedImage;
		}

		double[][] DCT = ImageUtils.applyDCT(prepareImage);
		double total = 0.0;
		for (int x = 0; x < 8; x++) {
			for (int y = 0; y < 8; y++) {
				total += DCT[x][y];
			}
		}
		total -= DCT[0][0];
		double average = total / 63;
		StringBuilder pHash = new StringBuilder();
		for (int x = 0; x < 8; x++) {
			for (int y = 0; y < 8; y++) {
				pHash.append((DCT[x][y] > average) ? "1" : "0");
			}
		}
		return pHash.toString();
	}

	/**
	 * <h3 class="en-US">Add text/image watermark to the target image</h3>
	 * <h3 class="en-US">添加文字/图片水印到目标图片</h3>
	 *
	 * @param graphics    <span class="en-US">target image Graphics2D object</span>
	 *                    <span class="zh-CN">目标图片的Graphics2D实例对象</span>
	 * @param width       <span class="en-US">image width</span>
	 *                    <span class="zh-CN">图片宽度</span>
	 * @param height      <span class="en-US">image height</span>
	 *                    <span class="zh-CN">图片高度</span>
	 * @param markOptions <span class="en-US">Mark options</span>
	 *                    <span class="zh-CN">水印选项</span>
	 */
	private static void markImage(final Graphics2D graphics, final int width, final int height,
	                              final MarkOptions markOptions) {
		Optional.ofNullable(markOptions.retrievePosition(width, height))
				.ifPresent(markPosition -> {
					switch (markOptions.getMarkType()) {
						case ICON:
							try {
								BufferedImage iconImg = ImageIO.read(FileUtils.getFile(markOptions.getMarkPath()));
								if (iconImg != null && markOptions.getTransparency() >= 0
										&& markOptions.getTransparency() <= 1) {
									graphics.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_ATOP,
											markOptions.getTransparency()));
									graphics.drawImage(iconImg, markPosition.getPositionX(), markPosition.getPositionY(), null);

									graphics.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER));
								}
							} catch (Exception e) {
								LOGGER.error("Water_Mark_Image_Error");
								if (LOGGER.isDebugEnabled()) {
									LOGGER.debug("Stack_Message_Error", e);
								}
							}
							break;
						case TEXT:
							if (markOptions.getMarkText() != null && markOptions.getFontName() != null
									&& markOptions.getFontSize() > 0) {
								graphics.setColor(markOptions.getColor());
								graphics.setFont(new Font(markOptions.getFontName(), Font.PLAIN, markOptions.getFontSize()));

								graphics.drawString(markOptions.getMarkText(), markPosition.getPositionX(), markPosition.getPositionY());
							}
							break;
					}
				});
	}

	/**
	 * <h3 class="en-US">Process image by given parameters</h3>
	 * <h3 class="en-US">根据给定的参数处理图片</h3>
	 *
	 * @param srcImage     <span class="en-US">Buffered image</span>
	 *                     <span class="zh-CN">缓冲图片实例对象</span>
	 * @param targetWidth  <span class="en-US">target width</span>
	 *                     <span class="zh-CN">图片调整后的宽度</span>
	 * @param targetHeight <span class="en-US">target height</span>
	 *                     <span class="zh-CN">图片调整后的高度</span>
	 * @param markOptions  <span class="en-US">Mark options</span>
	 *                     <span class="zh-CN">水印选项</span>
	 * @return <code>true</code>success	<code>false</code>failed
	 */
	private static BufferedImage processImage(@Nonnull final BufferedImage srcImage, final int targetWidth,
	                                          final int targetHeight, final MarkOptions markOptions) {
		if (targetWidth > 0 && targetHeight > 0) {
			BufferedImage bufferedImage = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_RGB);
			Graphics2D graphics = bufferedImage.createGraphics();
			graphics.drawImage(srcImage, 0, 0, targetWidth, targetHeight, null);

			Optional.ofNullable(markOptions)
					.ifPresent(options -> markImage(graphics, targetWidth, targetHeight, options));
			graphics.dispose();
			return bufferedImage;
		}
		return srcImage;
	}

	/**
	 * <h3 class="en-US">Convert bufferedImage to gray matrix</h3>
	 * <h3 class="en-US">转换缓冲图片实例对象为灰度二维数组</h3>
	 *
	 * @param bufferedImage <span class="en-US">Buffered image</span>
	 *                      <span class="zh-CN">缓冲图片实例对象</span>
	 * @return <span class="en-US">gray matrix</span>
	 * <span class="zh-CN">灰度二维数组</span>
	 */
	private static double[][] grayMatrix(final BufferedImage bufferedImage) {
		if (bufferedImage == null) {
			return new double[0][0];
		}
		int width = bufferedImage.getWidth();
		int height = bufferedImage.getHeight();
		double[][] grayMatrix = new double[height][width];
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				int pixel = bufferedImage.getRGB(x, y);
				grayMatrix[y][x] = ((pixel & 0xFF0000) >> 16) * 0.3
						+ ((pixel & 0xFF00) >> 8) * 0.59
						+ ((pixel & 0xFF) * 0.11);
			}
		}
		return grayMatrix;
	}

	/**
	 * <h3 class="en-US">Process Discrete Cosine Transform to bufferedImage</h3>
	 * <h3 class="en-US">对给定的缓冲图片实例对象做离散余弦变换</h3>
	 *
	 * @param bufferedImage <span class="en-US">Buffered image</span>
	 *                      <span class="zh-CN">缓冲图片实例对象</span>
	 * @return <span class="en-US">Process result</span>
	 * <span class="zh-CN">处理结果</span>
	 */
	private static double[][] applyDCT(final BufferedImage bufferedImage) {
		if (bufferedImage == null) {
			return new double[0][0];
		}
		int width = bufferedImage.getWidth();
		int height = bufferedImage.getHeight();
		int length = Math.max(width, height);
		double[] uv = new double[length];
		for (int i = 1; i < length; i++) {
			uv[i] = 1;
		}
		uv[0] = 1 / Math.sqrt(2.0);
		double[][] DCT = new double[width][height];
		for (int x = 0; x < width; x++) {
			for (int y = 0; y < height; y++) {
				double sum = 0.0;
				int pixel = bufferedImage.getRGB(x, y);
				double gray = ((pixel & 0xFF0000) >> 16) * 0.3
						+ ((pixel & 0xFF00) >> 8) * 0.59
						+ ((pixel & 0xFF) * 0.11);
				for (int i = 0; i < width; i++) {
					for (int j = 0; j < height; j++) {
						sum += Math.cos(((2 * i + 1) / (width * height * 1.0)) * x * Math.PI)
								* Math.cos(((2 * j + 1) / (width * height * 1.0)) * y * Math.PI)
								* gray;
					}
				}
				DCT[x][y] = sum * ((uv[x] * uv[y]) / 4.0);
			}
		}
		return DCT;
	}
}
