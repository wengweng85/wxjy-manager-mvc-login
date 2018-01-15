package com.insigma.mvc.service.sysmanager.login;


import java.util.List;

import com.insigma.mvc.model.SysLoginInf;
import com.insigma.mvc.model.SysPermission;
import com.insigma.mvc.model.SysRole;
import com.insigma.mvc.model.SysUser;


/**
 * 登录service接口
 * @author wengsh
 *
 */
public interface SysLoginService {
	/**
	 * 通过用户名获取会员表信息
	 * @param username
	 * @return
	 * @throws Exception 
	 */
	public SysUser getUserAndGroupInfo(String loginname) ;
	
	/**
	 * 通过用户id获取用户角色集合
	 * @param userid
	 * @return 角色集合
	 * @throws Exception 
	 */
	public List<SysRole> findRolesStr(String loginname) ;
	
	/**
	 * 通过用户id获取用户权限集合
	 * @param userid
	 * @return 权限集合
	 * @throws Exception 
	 */
	public List<SysPermission> findPermissionStr(String loginname) ;
	
	
	public void saveLoginHashInfo(SysLoginInf inf);
	
	
	public List<SysLoginInf> findLoginInfoByhashcode(String loginhash);
	

}
