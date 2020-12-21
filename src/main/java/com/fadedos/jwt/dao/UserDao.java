package com.fadedos.jwt.dao;

import com.fadedos.jwt.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/21
 */
@Mapper
@Repository
public interface UserDao {
    User login(User user);
}
