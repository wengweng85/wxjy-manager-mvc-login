package com.insigma.shiro.realm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;

import com.insigma.mvc.model.SysPermission;
import com.insigma.mvc.model.SysUser;

/**
 * 系统工具类
 * @author wengsh
 *
 */
public class SysUserUtil {

	public static final String SHIRO_CURRENT_USER_INFO="SHIRO_CURRENT_USER_INFO";
	public static final String SHIRO_CURRENT_PERM_LIST_INFO="SHIRO_CURRENT_PERM_LIST_INFO";
	
	
	 /** * 保存变量的ThreadLocal，保持在同一线程中同步数据. */
    private static final ThreadLocal SESSION_MAP = new ThreadLocal();

    /** * 工具类的protected构造方法. */
    protected SysUserUtil() {
    }

	 /**
	  *  setCurrentUser
	  * @param suser
	  */
    public static void setCurrentUser(SysUser suser) {  
        Map map = (Map) SESSION_MAP.get();
        if (map == null) {
            map = new HashMap();
            SESSION_MAP.set(map);
        }

        map.put(SHIRO_CURRENT_USER_INFO, suser);
    }  
   
    
    /**
	  *  setCurrentUser
	  * @param suser
	  */
   public static void removeCurrentUser() {  
       Map map = (Map) SESSION_MAP.get();
       if (map == null) {
           map = new HashMap();
           SESSION_MAP.set(map);
       }

       map.put(SHIRO_CURRENT_USER_INFO, null);
   }  
  
    /**
     * getCurrentUser
     * @return
     */
    public static SysUser getCurrentUser() {  
    	  Map map = (Map) SESSION_MAP.get();
    	  if(map!=null){
              return (SysUser)map.get(SHIRO_CURRENT_USER_INFO);
    	  }else{
    		  return null;
    	  }
    }  
    
    /**
     * 更新当前用户权限,系统内对用户做了权限修改后可以通过调用此方式动态修改当前用户权限
     */
   public static void updateCurrentUserPerms(){
		Subject subject = SecurityUtils.getSubject(); 
		RealmSecurityManager rsm = (RealmSecurityManager) SecurityUtils.getSecurityManager();  
		SysLoginShiroRealm shiroRealm = (SysLoginShiroRealm)rsm.getRealms().iterator().next();  
		String realmName = subject.getPrincipals().getRealmNames().iterator().next(); 
		//第一个参数为用户名,第二个参数为realmName
		SimplePrincipalCollection principals = new SimplePrincipalCollection(SysUserUtil.getCurrentUser().getUsername(),realmName); 
		subject.runAs(principals); 
		shiroRealm.getAuthorizationCache().remove(subject.getPrincipals()); 
		subject.releaseRunAs();
   }
   
	/**
    * 过滤三级菜单
    * @param sortlist
    */
   public static List<SysPermission> filterPersmList(List< SysPermission > permlist){
       List<SysPermission> resultlist=new ArrayList<SysPermission>();
       List<SysPermission> firstTempPermlist=new ArrayList<SysPermission>();
       
       //过滤掉按钮结点
       for(int i=0;i<permlist.size();i++) {
           if(permlist.get(i).getType().equals("3")){
           	    permlist.remove(i);
           	    i--;
           }
       }
       
       //先将第一级结点过滤出来
       for(int i=0;i<permlist.size();i++) {
           //如果是第一级
           if(permlist.get(i).getParentid().equals("0")){
             	firstTempPermlist.add(permlist.get(i));
           	    permlist.remove(i);
           	    i--;
           }
       }

       //再根据第一级节点过滤出第二级或三级结点
       for(int i=0;i<firstTempPermlist.size();i++){
       	   SysPermission firstTempPerm=firstTempPermlist.get(i);
           List<SysPermission> secondPersmList=new ArrayList<SysPermission>();
           for(int j=0;j<permlist.size();j++) {
           	SysPermission secondTempPerm=permlist.get(j);
               //第二级
               if(secondTempPerm.getParentid().equals(firstTempPerm.getPermissionid())){
                  List<SysPermission> thirdPermList=new ArrayList<SysPermission>();
                  for(int k=0;k<permlist.size();k++){
                   //第三级
                   if(permlist.get(k).getParentid().equals(secondTempPerm.getPermissionid())){
                   		  thirdPermList.add(permlist.get(k));
                       }
                   }
                   secondTempPerm.setChild(thirdPermList);
                   secondPersmList.add(secondTempPerm);
                   permlist.remove(j);
                   j--;
               }
           }
           if(secondPersmList.size()>0){
           	   firstTempPerm.setChild(secondPersmList);
           }
           resultlist.add(firstTempPerm);
       }
       return resultlist;
   }
   
   

}
