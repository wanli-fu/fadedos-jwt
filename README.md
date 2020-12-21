# 1. 什么是JWT

```mariadb
JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.
```

* 翻译
  jsonwebtoken(JWT)是一个开放标准(rfc7519),它定义了一种紧凑的,自包含的方式,用于在各方面之间以json对象安全的传输信息.`此信息可以验证和信任,因为它是数字签名.jwt可以使用秘密(hmac算法)或使用RSA或ECDSA的公钥/私钥对进行签名`

* 通俗解释

JWT是json web token,也就是通过json形式作为web应用中的令牌,用于在各方面之间安全的将信息作为json对象传输.在数据传输的过程中还可以完成数据加密,签名等相关处理

# 2.JWT能做什么

* 授权

  这是使用JWT的最常见方案.一旦用户登录,每个后续请求将包括JWT,从而允许用户访问该令牌允许的路由,服务和资源.单点登录是当今广泛使用jwt的一项功能.因为它的开销很小并且可以在不同的域中轻松使用

* 信息交换

  json web token 是在各方之间安全地传输信息的好方法.因为可以对jwt进行签名(例如,使用公钥/私钥对),所以您可以确保发件人是他们所说的人.此外由于签名是使用标头和有效的负载计算的,因此您还可以验证内容是否遭到篡改

# 3. 为什么是JWT

## 3.1 基于传统的session认证

* 认证方式

  我们知道,http是一种无状态的协议,而这就意味着如果用户向我们的应用提供了用户名和密码来进行认证,那么下一次用户请求时,用户还要再一次进行用户认证才行.因为根据http协议,我们并不知道是哪个用户发出的请求,所以为了让我们的应用能识别是那个用户发出的请求,我们只能在服务器存储一份用户登录的信息,这份登录信息会在响应时传递给浏览器,告诉其保存为cookie,以便下次请求时发送给我们的应用,这样我们的应用就能识别请求时来自哪个用户了,这就是基于传统的session认证

* 认证流程

  ![session认证流程](https://www.fadedos.xyz/upload/2020/12/session%E8%AE%A4%E8%AF%81%E6%B5%81%E7%A8%8B-f1341a5bbd794e188c14756b40236c2a.jpg)

* session暴露问题

  * 每个用户经过我们应用认证之后,我们的应用都在服务端做一次记录,以方便用户下次请求的鉴别,通常而言session都是保存在内存中的,而随着认证用户的增多,服务端的开销会明显增大

  * 用户认证之后,服务端做认证记录,如果认证的记录被保存在内存中的话,这意味这用户下次请求还必须要请求在这台服务器上,这样才能拿到授权的资源,这样在分布式的应用上,相应的限制了负载均衡器的能力.这也意味着限制了应用的扩展能力

  * 因为是基于cookie来进行用户识别的,cookie如果被截获,用户就会很容易受到跨站请求伪造的攻击

  * 在前后端分离项目

    也就是说前后端分离在应用解耦后增加了部署的复杂性.通常用户一次请求就要转发多次.如果使用session,每次携带sessionid到服务器,服务器还要查询用户信息.同时如果用户过多,这些信息存储在服务器内存中,总和服务器增加负担.还有CSRF(跨站伪造请求攻击),session是基于cookie进行用户识别的,cookie如果被截获,用户就会很容易受到跨站请求伪造的攻击.还有就是sessionid就是一个特征值,表达的信息不够丰富,不容易被扩展.而且如果你后端应用多节点部署,那么就需要实现session共享机制,不方便集群应用

  ![前后端分离 sessionid传递流程](https://www.fadedos.xyz/upload/2020/12/%E5%89%8D%E5%90%8E%E7%AB%AF%E5%88%86%E7%A6%BB%20sessionid%E4%BC%A0%E9%80%92%E6%B5%81%E7%A8%8B-d6671ff53e1d4c8d9033d1951d5e3dc3.jpg)

## 3.2 基于jwt认证

![基于JWT认证](https://www.fadedos.xyz/upload/2020/12/%E5%9F%BA%E4%BA%8EJWT%E8%AE%A4%E8%AF%81-0f0d2ccaf1f94a5799fbc7bf04819dd9.jpg)

* 认证流程
  * 首先,前端通过web表单将自己的用户名和密码发送到后端接口.这一过程一般是http post请求.建议的方式通过ssl加密的传输(https),从而避免敏感信息被嗅探
  * 后端核对用户名和密码成功后,将用户id等其他信息作为jwt payload(负载),将其与头部分别进行base64编码拼接后签名,形成一个jwt(token),形成的jwt就是一个形同lll.zzz.xxx的字符串. token head.payload.signature
  * 后端将JWT字符串作为登录成功的返回结果返回给前端.前端可以将返回的结果保存在localStorage或sessionStorage上,退出登录时前端删除保存的jwt即可
  * 前端在每次请求时将jwt放入http Header中Authorization位(解决xss和xsrf问题)
  * 后端检查是否存在,如果存在验证jwt的有效性.例如,检查签名是否正确;检查token是否过期;检查token的接收方是否是自己(可选)
  * 验证通过后后端使用JWT中包含的用户信息进行其他逻辑操作,返回相应结果
* JWT优势
  * 简洁(compact):可以通过url,post参数或者http header发送,因为数据量小,传输速度也很快
  * 自包含(self-contained):负载中包含了所有用户所需要的信息,避免了多次查询数据库
  * 因为token是以json加密的形式保存在客户端的,所以jwt是跨语言的,原则是任何web形式都支持的
  * 不需要在服务端保存会话信息,特别使用与分布式微服务

# 4.JWT的结构

* 令牌组成 jwt通常如下:xxx.xxx.xxx Header.payload.signature
  * 标头(header)
  * 有效负载(payload)
  * 签名(signature)

## 4.1 Header

标头通常是由两部分组成:令牌的类型(即JWT)和使用的签名算法,例如HMAC SHA256或RSA.`它会使用base64编码组成JWT结构的第一部分`

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

上面代码中，`alg`属性表示签名的算法（algorithm），默认是 HMAC SHA256（写成 HS256）；`typ`属性表示这个令牌（token）的类型（type），JWT 令牌统一写为`JWT`。

## 4.2 payload(负载)

令牌的第二部分是有效负载,其中包含声明.声明是有关实体(通常是用户)和其他数据的声明.`同样的,它会使用base64编码组成jwt结构的第二部分`

Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了7个官方字段，供选用。

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

* 注意此仅为base64编码,不要放用户的敏感信息,如密码等

## 4.3 signature

前面两步分都是使用base64进行编码,即前端可以解开知道里面的信息.signature需要使用编码后的header和payload以及我们提供了一个密钥.然后使用head而中指定的签名算法(hs256)进行签名.签名的作用保证jwt没有被篡改过

如:

```json
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

## 4.4 签名的目的

最后一步签名的过程,实际上是对头部以及负载内容进行签名,防止内容被篡改.如果有人对header以及payload的内容解码之后进行篡改,再进行编码,最后加上之前签名组合形成新的jwt的话,name服务器会判断出新的头部和负载形成的签名和JWT附带上的签名是不一样的.如果要对新的头部和负载进行签名,在不知道服务器加密时用密钥的话,的出来的签名也是不一样的

## 4.5 信息安全问题

base64是一种编码,是可逆的,那么我们的信息不就暴露了

是的,所以在JWT中,不应该在负载里加入任何敏感数据.在上面的例子中,我们传输的是用户user ID.这个值实际上不是什么敏感内容,一般情况下被知道也是安全的.但是像密码这样的内容就不能放在jwt中了.如果将用户的密码放在了jwt中,那么怀有恶意的第三方通过base64解码就能很快的知道你的密码了.因此jwt适用于向web传递些非敏感信息.jwt还经常用于设计用户认证和授权系统,甚至实现web应用的单点登录

## 4.6 放在一起

![jwt结构](https://www.fadedos.xyz/upload/2020/12/jwt%E7%BB%93%E6%9E%84-fc2da1566010494b8f35421464c06ccd.jpg)

* 输出是三个由点分隔的base64-URL字符串,可以在HTML和HTTP环境中轻松传递这些字符串,与基于xml的标准(例如SAML)相比,它更紧凑
* 简洁(compact)
* 可以通过url,post参数或者在HTTP header发送,因为数据量小,传递速度快
* 自包含(self-contained)
* 负载包含了所有用户所需要的信息,避免多次查询数据库

# 5. 使用JWT

* 引入依赖

  ```xml
      <!--引入jwt-->
      <dependency>
        <groupId>com.auth0</groupId>
        <artifactId>java-jwt</artifactId>
        <version>3.4.0</version>
      </dependency>
  ```

* 生成token 

  ```java
   @Test
      public void getToken() {
          //map 存放header信息
          Map<String, Object> map = new HashMap<>();
  
          //token 过期时间 当前时间60s后过期
          Calendar instance = Calendar.getInstance();
          instance.add(Calendar.SECOND,60);
  
          String token = JWT.create()
                  .withHeader(map) //指定header 一般使用默认的 可以不指定
                  .withClaim("userId", 21) //payload
                  .withClaim("username", "zhangsan")
                  .withExpiresAt(instance.getTime()) //指定令牌的过期时间
                  .sign(Algorithm.HMAC256("!hihkhkjhyi"));//签名
          System.out.println("token = " + token);
      }
  ```

  ```java
  //生成结果
  token = eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
      eyJleHAiOjE2MDg1NDM4MTEsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoiemhhbmdzYW4ifQ.
      BXIRDQgBXACVR3zlBBZ1ySTPItgabM1F-hWGRx3G90w
  ```

* 根据令牌和签名解析数据

  ```java
      @Test
      public void test() {
          //验证token
          //创建验证对象
          JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("!hihkhkjhyi")).build();
          DecodedJWT verify = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTM3MjgwMzEsInVzZXJJZCI6MjEsInVzZXJuYW1lIjoiemhhbmdzYW4ifQ.HRgL_UGCyIAHogTVEvgUTP4NsYpDRvjh6hw3dpVUiZE");
          //获取过期时间
          System.out.println(verify.getExpiresAt());
          //获取payload
          System.out.println(verify.getClaim("username").asString());
          System.out.println(verify.getClaim("userId").asInt());
  
  //        System.out.println(verify.getClaims().get("username").asString());
      }
  }
  ```

  ```java
  //输出结果
  Fri Feb 19 17:47:11 CST 2021
  zhangsan
  21
  ```

* 常见的异常信息

  * `TokenExpiredException`:token过期时间
  * `AlgorithmMismatchException`:算法不匹配异常
  * `InvalidClaimException`:失效的payload异常
  * `SignatureVerificationException`:签名不一致异常
  * `JWTDecodeException`:JWT解码异常

## 5.1 JWT的封装工具类

```java
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
    public static void verify(String token) {
         JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }

    /**
     * 获取token信息
     */
    public static DecodedJWT getTokenInfo(String  token) {
        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
        return verify;
    }
}
```

# 6.与springboot整合

[demo地址](https://github.com/wanli-fu/fadedos-jwt)


