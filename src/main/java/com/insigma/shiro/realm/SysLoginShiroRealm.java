package com.insigma.shiro.realm;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.pagehelper.StringUtil;
import com.insigma.mvc.model.SysPermission;
import com.insigma.mvc.model.SysRole;
import com.insigma.mvc.model.SysUser;
import com.insigma.mvc.service.sysmanager.login.SysLoginService;
import com.insigma.shiro.cache.RedisCache;
import com.insigma.shiro.token.CustomUsernamePasswordToken;

public class SysLoginShiroRealm extends AuthorizingRealm  {
	
	
	
	@Autowired
	private SysLoginService sysloginservice;
	
	
	@Autowired
    private RedisCache<String, Set<String>> redisCache;
	

	 /**
     * 认证
     */
	@Override
	public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authcToken) throws AuthenticationException,UnknownAccountException,LockedAccountException {
		CustomUsernamePasswordToken token = (CustomUsernamePasswordToken) authcToken;
		SimpleAuthenticationInfo authenticationInfo=null;
			
			//是否检验验证码
			if(token.getIsvercode().equals("1")){
		        //取得用户输入的校验码
		        String userInputValidCode =token.getVerifycode();

		        //取得真实的正确校验码
		        String realRightValidCode = (String) SecurityUtils.getSubject().getSession().getAttribute("session_validator_code");
		        
		        //清除校验码
		        SecurityUtils.getSubject().getSession().removeAttribute("session_validator_code");
		        
		        if (null == userInputValidCode || !userInputValidCode.equalsIgnoreCase(realRightValidCode)) {
		            throw new AuthenticationException("验证码不正确");
		        }
			}
			
			SysUser suser = sysloginservice.getUserAndGroupInfo(token.getUsername());
			if (suser == null) {
	            throw new UnknownAccountException();//没找到帐号
	        }
	
	        if (suser.getEnabled().equals("0") ) {
	            throw new LockedAccountException(); //帐号锁定
	        }
	    	authenticationInfo = new SimpleAuthenticationInfo(
			suser.getUsername(), 
			suser.getPassword(), 
	        getName() ); //realm name
	    	setSession(SysUserUtil.SHIRO_CURRENT_USER_INFO,suser);
	    	
	    	//用户权限
    	
	    	List<SysPermission> permlist=SysUserUtil.filterPersmList(sysloginservice.findPermissionStr(suser.getUsername()));
	    	setSession(SysUserUtil.SHIRO_CURRENT_PERM_LIST_INFO,permlist);
	    	suser.setPermlist(permlist);
	    	
	    	SysUserUtil.setCurrentUser(suser);
	        //清理缓存
	    	clearCachedAuthorizationInfo(authenticationInfo.getPrincipals());
	        return authenticationInfo;
	}
	
	
	/**
	 * 授权
	 */
	@Override
	public AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String loginname = (String) principals.getPrimaryPrincipal();
		try{
			if (StringUtil.isNotEmpty(loginname)) {
	            SimpleAuthorizationInfo authenticationInfo = new SimpleAuthorizationInfo();
 	           //用户角色
 	            List<SysRole> rolelist=sysloginservice.findRolesStr(loginname);
 	            if(rolelist!=null){
 	            	Set<String> roleset=new HashSet<String>();
 	 	            Iterator iterator_role=rolelist.iterator();
 	 	            while(iterator_role.hasNext()){
 	 	            	SysRole  srole=(SysRole) iterator_role.next();
 	 	            	roleset.add(srole.getCode());
 		            }
 	 	           authenticationInfo.setRoles(roleset);
 	            }
 	           
 	            //用户权限
	            List<SysPermission> permlist=sysloginservice.findPermissionStr(loginname);
	            if(permlist!=null){
	            	Set<String> set=new HashSet<String>();
	  	            Iterator iterator=permlist.iterator();
	  	            while(iterator.hasNext()){
	  	            	SysPermission  spermission=(SysPermission) iterator.next();
	  	            	set.add(spermission.getCode());
	  	            }
	   	            authenticationInfo.setStringPermissions(set);
	            }
	            return authenticationInfo;
	        }else{
	            return null;
	        }
		}catch(Exception e){
			e.printStackTrace();
		}
        return null;
	}
	
	/**
	 * 授权基于redis,权限信息将保存到redis服务器中
	 * @param principals
	 * @return
	 */
	public AuthorizationInfo doGetAuthorizationInfo_rediscache(PrincipalCollection principals) {
		String loginname = (String) principals.getPrimaryPrincipal();
		try{
			if (StringUtil.isNotEmpty(loginname)) {
	            SimpleAuthorizationInfo authenticationInfo = new SimpleAuthorizationInfo();
            	 //roles从缓存服务器中获取
	            Set<String> rolesset = redisCache.get(Constants.getUserRolesCacheKey(loginname));
	            if(rolesset!=null){
	            	authenticationInfo.setRoles(rolesset);
	            }else{
	            	//用户角色
	 	            List<SysRole> rolelist=sysloginservice.findRolesStr(loginname);
	 	            if(rolelist!=null){
	 	            	 Set<String> roleset=new HashSet<String>();
	 	 	            Iterator iterator_role=rolelist.iterator();
	 	 	            while(iterator_role.hasNext()){
	 	 	            	SysRole  srole=(SysRole) iterator_role.next();
	 	 	            	roleset.add(srole.getName());
	 	 	            	roleset.add(srole.getCode());
	 		            }
	 		            authenticationInfo.setRoles(roleset);
	 		            redisCache.put(Constants.getUserRolesCacheKey(loginname), rolesset);
	 	            }
	 	           
	            }
	            //permissions从缓存服务器中获取
	            Set<String> permissionsset = redisCache.get(Constants.getUserPermissionCacheKey(loginname));
	            if(permissionsset!=null){
	            	authenticationInfo.setStringPermissions(permissionsset);
	            }else{
	            	//用户权限
		            List<SysPermission> permlist=sysloginservice.findPermissionStr(loginname);
		            if(permlist!=null){
		                Set<String> set=new HashSet<String>();
			            Iterator iterator=permlist.iterator();
			            while(iterator.hasNext()){
			            	SysPermission  spermission=(SysPermission) iterator.next();
			            	set.add(spermission.getCode());
			            }
		 	            authenticationInfo.setStringPermissions(set);
		 	            redisCache.put(Constants.getUserPermissionCacheKey(loginname), permissionsset);
		            }
	            }
	            return authenticationInfo;
	        }
		}catch(Exception e){
			e.printStackTrace();
		}
        return null;
	}
	
	
	
	
	/**
	 * 清理缓存
	 * @param principal
	 */
    public void clearCachedAuthorizationInfo(String principal) {
        System.out.println("更新用户授权信息缓存");
    	SimplePrincipalCollection principals = new SimplePrincipalCollection(principal, getName());
        super.clearCachedAuthorizationInfo(principals);
        super.clearCache(principals);
        super.clearCachedAuthenticationInfo(principals);
    }
    
	/**
	 * 清理缓存 redis
	 * @param principal
	 */
    public void clearCachedAuthorizationInfo_rediscache(String principal) {
        System.out.println("更新用户授权信息缓存");
    	SimplePrincipalCollection principals = new SimplePrincipalCollection(principal, getName());
        super.clearCachedAuthorizationInfo(principals);
        super.clearCache(principals);
        super.clearCachedAuthenticationInfo(principals);
        redisCache.remove(Constants.getUserPermissionCacheKey(principal));
        redisCache.remove(Constants.getUserRolesCacheKey(principal));
    }

	/** 
     * 将一些数据放到ShiroSession中,以便于其它地方使用 
     * @see  比如Controller,使用时直接用HttpSession.getAttribute(key)就可以取到 
     */  
    private void setSession(Object key, Object value){  
        Subject subject = SecurityUtils.getSubject();  
        if(null != subject){  
            Session session = subject.getSession();  
            if(null != session){  
                session.setAttribute(key, value);  
            }  
        }  
    }

}
