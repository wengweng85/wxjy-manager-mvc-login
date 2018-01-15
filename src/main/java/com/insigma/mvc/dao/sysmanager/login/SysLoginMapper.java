package com.insigma.mvc.dao.sysmanager.login;


import java.util.List;

import com.insigma.mvc.model.SysGroup;
import com.insigma.mvc.model.SysLoginInf;
import com.insigma.mvc.model.SysPermission;
import com.insigma.mvc.model.SysRole;
import com.insigma.mvc.model.SysUser;


/**
 * 登录service接口
 * @author wengsh
 *
 */
public interface SysLoginMapper {
	/**
	 * 通过用户名获取会员表信息
	 * @param username
	 * @return 用户表
	 * @ 
	 */
	public SysUser getUserAndGroupInfo(String loginname)  ;
	
	
	/**
	 * 获取当前机构的行政区划信息
	 * @param groupid
	 * @return
	 * @
	 */
	public List<SysGroup> getGroupAreaInfo(String groupid)   ;
	
	
	/**
	 * 通过用户id获取用户角色集合
	 * @param userid
	 * @return 角色集合
	 * @ 
	 */
	public List<SysRole> findRolesStr(String loginname) ;
	
	
	/**
	 * 通过用户id获取用户权限集合
	 * @param userid
	 * @return 权限集合
	 * @ 
	 */
	public List<SysPermission> findPermissionStr(String loginname) ;
	
	
	/**
	 * 保存hashinfo
	 * @param hashinfo
	 */
	public void saveLoginHashInfo(SysLoginInf inf);
	
	
	public List<SysLoginInf> findLoginInfoByhashcode(String loginhash);

}
