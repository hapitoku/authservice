/**
 * 
 */
package com.eastcom_sw.sign.rest;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.eastcom_sw.frm.core.rest.BaseRestController;
import com.eastcom_sw.sign.service.UserService;

/**
 * @author cason
 *
 */
@RefreshScope
@RestController
@RequestMapping("/demo")
public class DemoController extends BaseRestController {
	@Autowired
	private UserService userService;
	
	@RequestMapping("/test")
	public String login(HttpServletRequest req){
		logger.info("Start login !!!");
		return userService.loadUser("hello").getUsername();
	}
}
