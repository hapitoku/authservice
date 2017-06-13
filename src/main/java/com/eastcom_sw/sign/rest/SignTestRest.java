package com.eastcom_sw.sign.rest;

import java.security.PrivateKey;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.eastcom_sw.frm.core.rest.BaseRestController;
import com.eastcom_sw.frm.core.service.ServiceException;
import com.eastcom_sw.sign.entity.User;
import com.eastcom_sw.sign.service.UserService;
import com.eastcom_sw.sign.utils.GeneratorConfig;

/**
 * OpenId Connect 授权接口服务
 * Created by Cason
 */
@RestController
public class SignTestRest extends BaseRestController {
    @Autowired(required = false)
    private GeneratorConfig generatorConfig;
    @Autowired
    private UserService userService;

    /**
     * AS核心代码  生成TOKEN
     * @param name
     * @param password
     * @return
     */
    @RequestMapping("/authorize")
    public String authorize(@RequestParam(name="username") String name,
    			@RequestParam(name="password") String password) {
    	//在服务开头与结尾加入日志信息，用于服务调用链跟踪
    	logger.info("login start!");
    	//判断用户名密码的有效性
    	{
	    	User u = null;
	    	u = userService.loadUser(name);
	    	if(u == null){
	    		throw new ServiceException("找不到用户 " + name);
	    	}
	    	if(!password.equals(u.getPassword())){
	    		throw new ServiceException("用户名密码不匹配 ");
	    	}
    	}
        //生成JwtClaims
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        //token 
        //设置token有效时间
        NumericDate date = NumericDate.now();
        date.addSeconds(3600);
        claims.setExpirationTime(date);
        claims.setNotBeforeMinutesInThePast(1);
        claims.setSubject("YOUR_SUBJECT");
        claims.setClaim("username", name);
        //使用私钥签名
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(generatorConfig.getKeyId());
        jws.setPayload(claims.toJson());
        PrivateKey privateKey = null;
        try {
            privateKey = new RsaJsonWebKey(JsonUtil.parseJson(generatorConfig.getPrivateKey())).getPrivateKey();
        } catch (JoseException e) {
            logger.info("私钥转换失败[{}]", e);
            return null;
        }
        jws.setKey(privateKey);
        String idToken = null;
        try {
        	//生成token
            idToken = jws.getCompactSerialization();
        } catch (JoseException e) {
            logger.info("获取ID TOKEN 失败[{}]", e);
            return null;
        }
        logger.info(idToken);
        
       	logger.info("login end!");
        return idToken;
    }

}
