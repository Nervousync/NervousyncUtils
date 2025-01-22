package org.nervousync.test.security;

import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.nervousync.security.factory.SecureFactory;
import org.nervousync.test.BaseTest;

public final class FactoryTest extends BaseTest {

    @Test
    @Order(20)
    public void config() {
        this.logger.info("Secure_Init_System_Result", SecureFactory.systemConfig(SecureFactory.SecureAlgorithm.SM4));
        this.logger.info("Secure_Init_Config_Result",
                SecureFactory.initConfig("TestConfig", SecureFactory.SecureAlgorithm.AES128));
    }

    @Test
    @Order(30)
    public void crypto() {
        String encResult = SecureFactory.encrypt("TestConfig", "TestString中文测试");
        this.logger.info("Secure_Encrypt_Result", encResult);
        this.logger.info("Secure_Decrypt_Result", SecureFactory.decrypt("TestConfig", encResult));
    }

    @Test
    @Order(35)
    public void override() {
        this.logger.info("Secure_Init_System_Result", SecureFactory.systemConfig(SecureFactory.SecureAlgorithm.AES256));
        SecureFactory.initialize(Boolean.TRUE);
    }

    @Test
    @Order(40)
    public void deregister() {
        this.logger.info("Secure_Register_Status", SecureFactory.registeredConfig("TestConfig"));
        this.logger.info("Secure_Remove_Result", SecureFactory.removeConfig("TestConfig"));
        this.logger.info("Secure_Register_Status", SecureFactory.registeredConfig("TestConfig"));
    }
}
