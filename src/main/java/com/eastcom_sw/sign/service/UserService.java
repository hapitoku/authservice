/**
 * 
 */
package com.eastcom_sw.sign.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.eastcom_sw.frm.core.service.BaseService;
import com.eastcom_sw.sign.dao.UserDao;
import com.eastcom_sw.sign.entity.User;

/**
 * 用于操作用户表的服务
 * @author cason
 *
 */
@Service
public class UserService extends BaseService {
	@Autowired
	private UserDao userDao;
	
	public User loadUser(final String username){
		return userDao.loadUser(username);
	}
}
