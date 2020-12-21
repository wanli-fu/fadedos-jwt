package com.fadedos.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/21
 */
public class JwtUtils {
    private static final String SING = "!Quhuu#@hihkhk&&";

    /**
     * 生成token  header.payload.signature
     */
    public static String getToken(Map<String, String> map) {

        Calendar instance = Calendar.getInstance();
        //默认7天失效
        instance.add(Calendar.DATE, 7);

        //创建jwt builder
        final JWTCreator.Builder builder = JWT.create();

        //payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });

        //指定令牌过期时间,签名 生成token
        String token = builder.withExpiresAt(instance.getTime())
                .sign(Algorithm.HMAC256(SING));
        return token;
    }


    /**
     * 验证token,合法性
     */
    public static DecodedJWT verify(String token) {

        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
        return verify;
    }

    /**
     * 获取token信息
     */
    public static DecodedJWT getTokenInfo(String  token) {
        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
        return verify;
    }
}
