package com.fadedos.jwt.interceptors;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fadedos.jwt.entity.User;
import com.fadedos.jwt.util.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/22
 */
@Slf4j
public class JwtInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HashMap<String, Object> map = new HashMap<>();

        //获取请求头的令牌
        String token = request.getHeader("token");

        try {
            //验证令牌
            JwtUtils.verify(token);

            //验证成功直接,放行请求
            return true;
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
        //设置状态
        map.put("state", false);
        //将map转换为jsn,给前端友好提示
        //@ResponseBody 底层用是Jackson
        String json = new ObjectMapper().writeValueAsString(map);

        //响应前端,设定响应格式
        response.setContentType("application/json;charset=UTF-8");
        //返回前端
        response.getWriter().println(json);
        return false;
    }
}
