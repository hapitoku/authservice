package com.eastcom_sw.sign.utils;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 自动读入key相关信息
 * 授权API的keyId是固定的
 * 该配置信息也可放在配置中心，可随时修改并热生效（现在写在application.properties中）
 * Created by liang on 2017/5/10.
 */
@Configuration
@ConfigurationProperties(prefix = "auth.token")
public class GeneratorConfig {
    private String keyId;
    private String publicKey;
    private String privateKey;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
}
