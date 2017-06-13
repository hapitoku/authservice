package com.eastcom_sw.sign;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;

import com.eastcom_sw.frm.sign.Request;
import com.eastcom_sw.frm.sign.constant.HttpHeader;
import com.eastcom_sw.frm.sign.constant.HttpSchema;
import com.eastcom_sw.frm.sign.enums.Method;
import com.eastcom_sw.frm.sign.util.SignUtil;
import com.eastcom_sw.sign.utils.GenerateToken;
import com.eastcom_sw.sign.utils.MessageDigestUtil;

/**
 * Created by liang on 2017/5/10.
 */
@SpringBootTest
public class GenerateRsa {

    private Logger logger = LoggerFactory.getLogger(getClass());
    private static final String keyId = "1cabd2bd2b9f43b48640e74f677a94f4";
    private static final String pubjson = "{\"kty\":\"RSA\",\"kid\":\"1cabd2bd2b9f43b48640e74f677a94f4\",\"alg\":\"ES256\",\"n\":\"hca-H7abmqWvUtlZfm0mbKlpyYaMZ5F-E_Bd-ZAMoy0mx5-veqbDbwPEUp9ur9vbQ30Q0vbQ5OwXznpYXJL9X_m77v5_qD5S8T727DyQwWiIjF_viOYK7AG3j2uIW_24LjsUxLxJUIYNR0CVWDu723G06z-0N5r8be66dbnN2E_NLH0wdqxMAY2UaL7-Hs5gwzB618juMmWTSmnTRATrILSAnSgwrofMpfPrGzAOxNx_T6HqEVR07GSoVekuibzkCq6h-YNTIkKBHYwHRBKZ1r97-dOudx2lDicmVskaRM6Da6WtoXRHJbNQj4CHw_kUnv08mWWWfCA89-DljNhg0Q\",\"e\":\"AQAB\"}";
    private static final String prijson = "{\"kty\":\"RSA\",\"kid\":\"1cabd2bd2b9f43b48640e74f677a94f4\",\"alg\":\"ES256\",\"n\":\"hca-H7abmqWvUtlZfm0mbKlpyYaMZ5F-E_Bd-ZAMoy0mx5-veqbDbwPEUp9ur9vbQ30Q0vbQ5OwXznpYXJL9X_m77v5_qD5S8T727DyQwWiIjF_viOYK7AG3j2uIW_24LjsUxLxJUIYNR0CVWDu723G06z-0N5r8be66dbnN2E_NLH0wdqxMAY2UaL7-Hs5gwzB618juMmWTSmnTRATrILSAnSgwrofMpfPrGzAOxNx_T6HqEVR07GSoVekuibzkCq6h-YNTIkKBHYwHRBKZ1r97-dOudx2lDicmVskaRM6Da6WtoXRHJbNQj4CHw_kUnv08mWWWfCA89-DljNhg0Q\",\"e\":\"AQAB\",\"d\":\"WWymMQrfb3wr-8ThBxstoVuKJLW1a5IdZnS6TRYW7IlFMBI1ulZ5s98fwF9lHVdpde7HbU6iCzUrINI1-QQlLaACGdu0OCIZTbzaUMaXuUIIbVXACJJGYMcxDkVCrMOo9_Z0hqKam6JQg_3PF2EuzZ1v5AX8kWMgNNhtej7PNDYErLj5B9_r-eAzB3S-TM_PwUFyQgvR8svJonTU8Rb3KamemZa4ZQh_19cnJFZUv47BdlSbfS0oK1qh9YNZssADLLtmdvSzUczSrmJ1kl8vX_yzgCqKcTex1By-DOrsKBmBtfzX3PNL33A1xF0gTaAELcwbJWrCo3aNmVqoNIPqJQ\",\"p\":\"vE_4H7iIx7EPwxK165tYU8J2HQX3tABYI-9EMijz8PXDt-MZhk74u7FwOAKc7fwzz7bgXV6g7HAyd3nAp3BMgt7GeHRB5VvK6uoruYhYVYnUYSo1X2Flk9a7zSDUrXWaOjGMfbOQaB9jPdDQ8WnM29A2O6aSMzGOlfSLjBlDjH8\",\"q\":\"tdyBGtvafCzwNKquOV6v4Y5AcBbpNBReaZBME9mf_aEZL1IcQflQnfDAUJgi-Ot3S8_QRUMOeWlhiJCg7sxjPOVxKD0cNCwn3cDz7fDmQ6yYJxhM2iaondwxPsDPMIP583VTSl3efYVQ497TdnolkrY4mkS8PELLwSJcc7Ahqq8\",\"dp\":\"S-ohKQiHe5lRtV5xoE27yeh3HTQuq44H-lSWtXH1BYrOH--Zdp-XfnMFvk6vXPFzIaWjxYBEd4yzi561n8qRzaBpel3DwubCYvmMLvtcQP-TcqhFY_IrtPG4O_WkR1lFl3gqHvKooJEmvODVmr0ALQ0_D8US4zhzNtii-ROmO5k\",\"dq\":\"NR1646JUtLHXUjqLehwKmIEYluRKJjjQvlozrhSAou4bUfPUZvxvLEH1mVRl2nfDNvQyKxiDsLgzkVRUfIpbbZzBqPP4OdCvsBe75sHWLuvI4Jo7T_e8haabB23-1XemWBHrSqwR4G1Ai903u8G_GZN5Aq2SoLMNmZH0mKFXo-c\",\"qi\":\"WWQDyUdXf4m9W753CIFej2dz9rfi-wiQeXCRgrfPNjVbRVgDDG84_3BRDf0mQLLrrw_DeVX54N-fQ-vl6Tr_r19WcpTBBPJ8Jyd_1xPV8rVIFpndSnR9IZTaMW1nXr6xP_0qWrrLhFz5SgTnnYVLgE0k8XjAT8nEm6-MVnTGLUs\"}";


    /**
     * 生成RSA  公钥 私钥
     * @throws JoseException
     */
    @Test
    public void generateRsa() throws JoseException {
        logger.info("KEYID [{}]", keyId);
        GenerateToken.generateRsa(keyId);
    }

    @Test
    public void test() throws Exception {
        String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QxMTEifQ.eyJqdGkiOiJnQ3lPWEJvcW5BM0NZQzd4bHR6NG53IiwiaWF0IjoxNDk2MzcxODA4LCJleHAiOjE0OTYzNzE5MjgsIm5iZiI6MTQ5NjM3MTc0OCwic3ViIjoiWU9VUl9TVUJKRUNUIiwidXNlcm5hbWUiOiJ6aGFuZ3NhbiJ9.ftHgjyxkpRpnnWCq0g8vkCFoxuqsPTjKRtEOI27J5ZlEU7rKh5sEQac-NoiPE6kBms_wKayFknr0S5qvk-RnEateMAUsr3GVH-kEsplvIsF2niP_uE_9cQ12b9SOIG8ka0ZT1vCplbVD8GvwXspCBzOgkvSfjqQIDYCvgR_usZkV0Bv83Fk3lWmSk1ZVBW0e_oI1a5ACjfjgbw2AojoMK9jPIfsGWlyYtJq2rrHZkO-jsromdyGYDp96dFt6U96U4o4whh4E93YFmyauQo36MN-h8gYYCUvyMqmK8uUQpHD_Hkb7lhddPQZJaN-JnmqDQHus6_seECOjH2_WnH3gAw";
        String publicKey = "{\"kty\":\"RSA\",\"kid\":\"1cabd2bd2b9f43b48640e74f677a94f4\",\"alg\":\"RS256\",\"n\":\"y2cgflb6rTmCr8mzxhDMQlqd1O9SMu4l0yIwzFr5bs9x8hujByZBfW4rOFkr9wWsEjoz8qEogAtNA8GHlTAu_HPcKF274tb-7uHYJ5ejuJuzbBY1gUpEVW3XDCFC0vHZy6j0VZhpwOkRP3LWMBDJ_Jj8FMzJmkPWkO0VQEd8Gq-7U6bItgdPBfy6BcRsV5O88brHoEF9E15pEu_Hpu5IO-wz4Q2z4g5h4VeRg0MWT4r63oraqy-dX5QrMFuJnYVl8iNL2s-sKVG0ELQx-ZUiqrLExunmF8BvXcCCKsce6VKU9KU-LYLNjw-W7TuR67uNWavTi9tJtrZn59lc9MDMLw\",\"e\":\"AQAB\"}";
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

//        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
//                .setRequireExpirationTime()
//                .setRequireSubject();
    }

//    /**
//     * RS 核心代码
//     * 验证PublicKey
//     * @throws Exception
//     */
//    @Test
//    public void validateToken() throws Exception {
//        String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFjYWJkMmJkMmI5ZjQzYjQ4NjQwZTc0ZjY3N2E5NGY0In0.eyJqdGkiOiI4RlFtQlA4OGZxcmJHR3I3WjA1VkJBIiwiaWF0IjoxNDk1MzU3MDQxLCJleHAiOjE0OTUzNTcxNjEsIm5iZiI6MTQ5NTM1Njk4MSwic3ViIjoiWU9VUl9TVUJKRUNUIiwiYXVkIjoiWU9VUl9BVURJRU5DRSJ9.Z-3GtgfYQLjJfApQCnYnk1EVGiGny7nnsFFyIos5mdPOBP1PkE5C0lqDkoIK5bzCe6i75bGEQozSPY4r0q3OAzu2C1L_TtCRle3suOtjrW_radKEB6wmKV4Q4hlaRj9uEYggkUU1RxdnEIJzFentEw6_tq2mOsaFbsdCLtFSioindAV0QDovdiuvS35JgfoGXXG2s6JELyCpp4DNgRxVzbhtOOl6w9MNVkdZCu-Iqh3-yJ4Mj-qJgTPbGXw9cxAq-Oeo02hVJkWZlhb3i73wydxceNoEQw-oPTyGpbO6JOK3Lb8PGSEz00W5vZWgwG_nEGxrQrVfkjgu3dhraBGjMQ";
//        String publicKey = "{\"kty\":\"RSA\",\"kid\":\"1cabd2bd2b9f43b48640e74f677a94f4\",\"alg\":\"ES256\",\"n\":\"j-cXGLN90kaK2Mkz0aG3Y6BkUo6S8rO1VwJLxjfFrQNvuRYiNyc0CCzu4XbGfo0Sz-C7iemLngq_s_QIp8xCRyfVWe0Tfxnz8TqisPl0B4Eo2gt05rdXFer6EWVA-4ibpjifmhIpLcQ2nf194TJmqimKjg8lxVLxflpinx6TApiDVD7FNdXDHq9xOa_plTTrIB2nAurpM-4aWRENLBa9MQOslsz5_42iRPjmIvL_RGQW90EIyJM7erLbAC4qH_qwWlQG2t3RBzcf1p2RO8qHgRlAZMSAEwpbwev7eKniZlrP8fWF-2z1KYaagYQvrIFMEdcbCSwNdPomMG2sufB3tw\",\"e\":\"AQAB\"}";
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        PublicKey pk = new RsaJsonWebKey(JsonUtil.parseJson(publicKey)).getPublicKey();
//        Claims claims = GenerateToken.validateToken(token, pk);
//        System.out.println(claims.toString());
//    }

    /**
     * 生成JwtClaims
     * @throws JoseException
     */
    @Test
    public void generateClaims() throws JoseException {
        JwtClaims claims;
        claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        //expire time
        NumericDate date = NumericDate.now();
        date.addSeconds(120);
        claims.setExpirationTime(date);
        claims.setNotBeforeMinutesInThePast(1);
        claims.setSubject("YOUR_SUBJECT");
        claims.setAudience("YOUR_AUDIENCE");
        //私钥签名
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(keyId);
        jws.setPayload(claims.toJson());
        PrivateKey privateKey = new RsaJsonWebKey(JsonUtil.parseJson(prijson)).getPrivateKey();
        jws.setKey(privateKey);
        String idToken = jws.getCompactSerialization();
        logger.info(idToken);

        //公钥解密验证
        JsonWebSignature jws2 = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKeyIdHeaderValue(keyId);
        PublicKey publicKey = new RsaJsonWebKey(JsonUtil.parseJson(pubjson)).getPublicKey();
        jws.setKey(publicKey);
        jws.setCompactSerialization(idToken);
        String payload = jws.getPayload();
        logger.info(payload);

    }


    @Test
    public void testSign(){

        String body = "demo string body content";
        Map<String, String> headers = new HashMap<>();
        //（必填）根据期望的Response内容类型设置
        headers.put(HttpHeader.HTTP_HEADER_ACCEPT, "application/json");
        //（可选）Body MD5,服务端会校验Body内容是否被篡改,建议Body非Form表单时添加此Header
        headers.put(HttpHeader.HTTP_HEADER_CONTENT_MD5, MessageDigestUtil.base64AndMD5(body));
        //（POST/PUT请求必选）请求Body内容格式
        headers.put(HttpHeader.HTTP_HEADER_CONTENT_TYPE, "application/text; charset=UTF-8");

        Map<String, String> query = new HashMap<>();

        headers.put("a-header1", "header1Value");
        headers.put("b-header2", "header2Value");
        List<String> CUSTOM_HEADERS_TO_SIGN_PREFIX = new ArrayList<>();
        CUSTOM_HEADERS_TO_SIGN_PREFIX.clear();
        CUSTOM_HEADERS_TO_SIGN_PREFIX.add("a-header1");
        CUSTOM_HEADERS_TO_SIGN_PREFIX.add("a-header2");

        Request request = new Request(Method.GET, HttpSchema.HTTP+"10.8.132.164:6002", "/lc/log/query", "KEY", "SEC", 300);
        request.setHeaders(headers);
        request.setSignHeaderPrefixList(CUSTOM_HEADERS_TO_SIGN_PREFIX);
        request.setStringBody(body);

        String sign1 = SignUtil.sign(request.getAppSecret(), "GET", request.getPath(), request.getHeaders(), request.getQuerys(), request.getBodys(), CUSTOM_HEADERS_TO_SIGN_PREFIX);
        System.out.println(sign1);
    }
}
