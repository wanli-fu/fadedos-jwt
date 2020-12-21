package com.fadedos.jwt.controller;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fadedos.jwt.entity.User;
import com.fadedos.jwt.service.UserService;
import com.fadedos.jwt.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/21
 */
@RestController
@Slf4j
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/user/login")
    public Map<String, Object> login(User user) {
        log.info("用户名:[{}]", user.getName());
        log.info("密码:[{}]", user.getPassword());

        HashMap<String, Object> map = new HashMap<>();

        try {
            User userDB = userService.login(user);

            HashMap<String, String> payload = new HashMap<>();
            payload.put("name", userDB.getName());
            payload.put("password", userDB.getPassword());

            //生成token
            String token = JwtUtils.getToken(payload);

            map.put("state", true);
            map.put("msg", "认证成功");
            //响应token
            map.put("token", token);
        } catch (Exception e) {
            map.put("state", false);
            map.put("msg", "认证失败");
        }
        return map;
    }

    @PostMapping("/user/test")
    public Map<String, Object> test(String token) {
        log.info("当前token为:[{}]", token);
        HashMap<String, Object> map = new HashMap<>();

        try {
            //验证令牌
            DecodedJWT verify = JwtUtils.verify(token);
            map.put("state", true);
            map.put("msg", "请求成功");
            return map;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "无效签名");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "token过期");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "token算法不一致");
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            map.put("msg", "token解码异常 ");
        }
        map.put("state", false);
        return map;
    }
}
