package com.eastcom_sw.sign.utils;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 用于生成 公钥 私钥
 * Created by liang on 2017/4/7.
 */
public class GenerateToken {
    private static Logger logger = LoggerFactory.getLogger(GenerateToken.class);

    /**
     * 生成RSA  公钥 私钥
     * @throws JoseException
     */
    public static void generateRsa(String keyId) throws JoseException {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(keyId);
        jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        String publicKey = jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        String privateKey = jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);

        logger.info("公匙[{}]", publicKey);
        logger.info("私匙[{}]", privateKey);
    }

    public static void main(String[] args) throws Exception {
    	generateRsa("test111");
    }
}
