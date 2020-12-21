package com.fadedos.jwt.entity;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @Description:TODO
 * @author: pengcheng
 * @date: 2020/12/21
 */
@Data
@Accessors(chain = true)
public class User  {
    private int id;
    private String name;
    private String password;
}
