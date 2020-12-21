package com.fadedos.jwt.service.impl;

import com.fadedos.jwt.dao.UserDao;
import com.fadedos.jwt.entity.User;
import com.fadedos.jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/21
 */
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserDao userDao;
    @Override
    public User login(User user) {
        //根据接收用户名密码查询数据库
        User userDB = userDao.login(user);
        if (userDB != null) {
            return userDB;
        }
        throw new RuntimeException("登录失败~~");
    }
}
