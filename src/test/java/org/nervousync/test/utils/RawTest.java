package org.nervousync.test.utils;

import org.junit.jupiter.api.*;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.test.BaseTest;
import org.nervousync.utils.ConvertUtils;
import org.nervousync.utils.RawUtils;
import org.nervousync.utils.StringUtils;

import java.nio.ByteOrder;

public class RawTest extends BaseTest {

    private static final int POSITION = 27;
    private static final int RANDOM_LENGTH = 27;
    private static final int ARRAY_LENGTH = 64;
    private byte[] dataBytes;

    @BeforeEach
    public final void init() {
        this.dataBytes = new byte[ARRAY_LENGTH];
    }

    @AfterEach
    public void print() {
        this.logger.debug("Raw_Data_Bytes", ConvertUtils.toHex(this.dataBytes));
    }

    @Test
    @Order(100)
    public void testBoolean() throws DataInvalidException {
        RawUtils.writeBoolean(this.dataBytes, Boolean.TRUE);
        Assertions.assertTrue(RawUtils.readBoolean(this.dataBytes));
    }

    @Test
    @Order(101)
    public void testBooleanPosition() throws DataInvalidException {
        RawUtils.writeBoolean(this.dataBytes, POSITION, Boolean.TRUE);
        Assertions.assertTrue(RawUtils.readBoolean(this.dataBytes, POSITION));
    }

    @Test
    @Order(110)
    public void testShort() throws DataInvalidException {
        RawUtils.writeShort(this.dataBytes, Short.MAX_VALUE);
        Assertions.assertEquals(Short.MAX_VALUE, RawUtils.readShort(this.dataBytes));
    }

    @Test
    @Order(111)
    public void testShortPosition() throws DataInvalidException {
        RawUtils.writeShort(this.dataBytes, POSITION, Short.MAX_VALUE);
        Assertions.assertEquals(Short.MAX_VALUE, RawUtils.readShort(this.dataBytes,  POSITION));
    }

    @Test
    @Order(112)
    public void testShortLittle() throws DataInvalidException {
        RawUtils.writeShort(this.dataBytes, ByteOrder.LITTLE_ENDIAN, Short.MAX_VALUE);
        Assertions.assertEquals(Short.MAX_VALUE, RawUtils.readShort(this.dataBytes, ByteOrder.LITTLE_ENDIAN));
    }

    @Test
    @Order(120)
    public void testInt() throws DataInvalidException {
        RawUtils.writeInt(this.dataBytes, Integer.MAX_VALUE);
        Assertions.assertEquals(Integer.MAX_VALUE, RawUtils.readInt(this.dataBytes));
    }

    @Test
    @Order(121)
    public void testIntPosition() throws DataInvalidException {
        RawUtils.writeInt(this.dataBytes, POSITION, Integer.MAX_VALUE);
        Assertions.assertEquals(Integer.MAX_VALUE, RawUtils.readInt(this.dataBytes, POSITION));
    }

    @Test
    @Order(122)
    public void testIntLittle() throws DataInvalidException {
        RawUtils.writeInt(this.dataBytes, ByteOrder.LITTLE_ENDIAN, Integer.MAX_VALUE);
        Assertions.assertEquals(Integer.MAX_VALUE, RawUtils.readInt(this.dataBytes, ByteOrder.LITTLE_ENDIAN));
    }

    @Test
    @Order(130)
    public void testLong() throws DataInvalidException {
        RawUtils.writeLong(this.dataBytes, Long.MAX_VALUE);
        Assertions.assertEquals(Long.MAX_VALUE, RawUtils.readLong(this.dataBytes));
    }

    @Test
    @Order(131)
    public void testLongPosition() throws DataInvalidException {
        RawUtils.writeLong(this.dataBytes, POSITION, Long.MAX_VALUE);
        Assertions.assertEquals(Long.MAX_VALUE, RawUtils.readLong(this.dataBytes, POSITION));
    }

    @Test
    @Order(132)
    public void testLongLittle() throws DataInvalidException {
        RawUtils.writeLong(this.dataBytes, ByteOrder.LITTLE_ENDIAN, Long.MAX_VALUE);
        Assertions.assertEquals(Long.MAX_VALUE, RawUtils.readLong(this.dataBytes, ByteOrder.LITTLE_ENDIAN));
    }

    @Test
    @Order(140)
    public void testString() throws DataInvalidException {
        String randomString = StringUtils.randomString(RANDOM_LENGTH);
        RawUtils.writeString(this.dataBytes, randomString);
        Assertions.assertEquals(RawUtils.readString(this.dataBytes, RANDOM_LENGTH), randomString);
    }

    @Test
    @Order(141)
    public void testStringPosition() throws DataInvalidException {
        String randomString = StringUtils.randomString(RANDOM_LENGTH);
        RawUtils.writeString(this.dataBytes, POSITION, randomString);
        Assertions.assertEquals(RawUtils.readString(this.dataBytes, POSITION, RANDOM_LENGTH), randomString);
    }

    @Test
    @Order(142)
    public void testStringLittle() throws DataInvalidException {
        String randomString = StringUtils.randomString(RANDOM_LENGTH);
        RawUtils.writeString(this.dataBytes, ByteOrder.LITTLE_ENDIAN, randomString);
        Assertions.assertEquals(RawUtils.readString(this.dataBytes, RANDOM_LENGTH, ByteOrder.LITTLE_ENDIAN), randomString);
    }

    @Test
    @Order(143)
    public void testStringEncoding() throws DataInvalidException {
        String randomString = "中文测试中文测试";
        RawUtils.writeString(this.dataBytes, randomString, "GB2312");
        Assertions.assertEquals(randomString, RawUtils.readString(this.dataBytes, 16, "GB2312"));
    }

    @Test
    @Order(144)
    public void testStringEncodingPosition() throws DataInvalidException {
        String randomString = "中文测试中文测试";
        RawUtils.writeString(this.dataBytes, POSITION, randomString, "GB2312");
        Assertions.assertEquals(randomString, RawUtils.readString(this.dataBytes, POSITION, 16, "GB2312"));
        Assertions.assertNotEquals(randomString, RawUtils.readString(this.dataBytes, POSITION, 16));
    }

    @Test
    @Order(145)
    public void testStringDefault() throws DataInvalidException {
        String randomString = StringUtils.randomString(ARRAY_LENGTH);
        RawUtils.writeString(this.dataBytes, randomString);
        Assertions.assertEquals(RawUtils.readString(this.dataBytes), randomString);
    }
}
