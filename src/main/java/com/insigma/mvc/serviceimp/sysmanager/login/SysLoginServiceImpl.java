package com.insigma.mvc.serviceimp.sysmanager.login;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.insigma.mvc.dao.sysmanager.login.SysLoginMapper;
import com.insigma.mvc.model.SysGroup;
import com.insigma.mvc.model.SysLoginInf;
import com.insigma.mvc.model.SysPermission;
import com.insigma.mvc.model.SysRole;
import com.insigma.mvc.model.SysUser;
import com.insigma.mvc.service.sysmanager.login.SysLoginService;


/**
 * 登录service接口
 * @author wengsh
 *
 */

@Service
public class SysLoginServiceImpl implements SysLoginService {

	//登录dao
	@Resource
	private SysLoginMapper sysloginmapper;
	
	@Override
	public SysUser getUserAndGroupInfo(String loginname)  {
		SysUser suser=sysloginmapper.getUserAndGroupInfo(loginname);
		if(suser==null){
			return null;
		}else {
			List<SysGroup> list=sysloginmapper.getGroupAreaInfo(suser.getGroupid());
			for (SysGroup sgroup : list) {
				Object type =sgroup.getType();
				if("1".equals(type)){//当前数据为行政区划
					suser.setAab301(sgroup.getGroupid());
					suser.setAab301name(sgroup.getName());
				    break;
				}
			}
			return suser;
		}
	}

	@Override
	public List<SysRole> findRolesStr(String loginname)  {
		List<SysRole> list= sysloginmapper.findRolesStr(loginname);
		return list;
	}

	@Override
	public List<SysPermission>  findPermissionStr(String loginname)  {
		List<SysPermission> list=sysloginmapper.findPermissionStr(loginname);
		return list;
	}

	@Override
	public void saveLoginHashInfo(SysLoginInf inf) {
		sysloginmapper.saveLoginHashInfo(inf);
	}

	@Override
	public List<SysLoginInf> findLoginInfoByhashcode(String loginhash) {
		return sysloginmapper.findLoginInfoByhashcode(loginhash);
	}


}
