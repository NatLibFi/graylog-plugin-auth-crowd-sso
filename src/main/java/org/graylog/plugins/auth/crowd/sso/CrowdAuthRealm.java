/**
*
* Crowd SSO authentication plugin for Graylog
*
* Copyright (C) 2018 University Of Helsinki (The National Library Of Finland)
*
* This file is part of graylog-plugin-auth-crowd-sso
*
* graylog-plugin-auth-crowd-sso program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* graylog-plugin-auth-crowd-sso is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU eneral Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/
package org.graylog.plugins.auth.crowd.sso;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.cache.MapCache;
import org.graylog2.database.NotFoundException;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.database.users.User;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.graylog2.shared.users.Role;
import org.graylog2.shared.users.UserService;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.users.RoleService;
import org.graylog2.users.RoleImpl;
import org.graylog2.utilities.IpSubnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Cookie;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Optional;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.List;
import java.util.Collection;
import java.io.IOException;

public class CrowdAuthRealm extends AuthenticatingRealm {
  private static final Logger LOG = LoggerFactory.getLogger(CrowdAuthRealm.class);

  public static final String NAME = "crowd-sso";

  private final UserService userService;
  private final ClusterConfigService clusterConfigService;
  private final RoleService roleService;

  @Inject
  public CrowdAuthRealm(UserService userService,
  ClusterConfigService clusterConfigService,
  RoleService roleService) {
    this.userService = userService;
    this.clusterConfigService = clusterConfigService;
    this.roleService = roleService;
    setAuthenticationTokenClass(HttpHeadersToken.class);
    setCredentialsMatcher(new AllowAllCredentialsMatcher());
    setCacheManager(new MemoryConstrainedCacheManager());
    setCachingEnabled(true);
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    HttpHeadersToken headersToken = (HttpHeadersToken) token;
    final CrowdAuthConfig config = clusterConfigService.getOrDefault(
    CrowdAuthConfig.class,
    CrowdAuthConfig.defaultConfig());

    final CrowdApi crowdApi = new CrowdApi(
    config.apiUrl(),
    config.applicationName(),
    config.applicationPassword(),
    config.apiVerifyCert()
    );

    final MultivaluedMap<String, String> requestHeaders = headersToken.getHeaders();
    final String cookieValue = getCookieValue(requestHeaders, config.cookieName());

    if (cookieValue == null) {
      LOG.trace("No Crowd sessions tokens found");
      return null;
    } else {
      try {
        Map<String, String> userDetails = crowdApi.authenticateUser(cookieValue);
        User user = userService.load(userDetails.get("userName"));

        if (user == null) {
          if (config.autoCreateUser()) {
            user = userService.create();
            user.setName(userDetails.get("userName"));
            user.setExternal(true);
            user.setPermissions(Collections.emptyList());
            user.setPassword("dummy password");
            user.setFullName(userDetails.get("display-name"));
            user.setEmail(userDetails.get("email"));
          }
        }

        if (user == null) {
          LOG.trace(
          "No user named {} found and automatic user creation is disabled",
          userDetails.get("userName")
          );
          return null;
        } else {
          if (config.autoCreateRole()) {

            Set<String> roleIds = new HashSet<String>();
            Set<String> groups = crowdApi.getUserGroups(userDetails.get("userName"));

            for (String group : groups) {
              Role role;

              if (roleService.exists(group)) {
                role = roleService.load(group);
              } else {
                Set<String> permissions = new HashSet<String>(1);
                role = new RoleImpl();

                permissions.add("reader");

                role.setName(group);
                role.setPermissions(permissions);
                roleService.save(role);
              }

              roleIds.add(role.getId());
            }

            user.setRoleIds(roleIds);
          }

          userService.save(user);
          ShiroSecurityContext.requestSessionCreation(true);

          CacheManager CacheManager = getCacheManager();
          Cache<String, String> cache = CacheManager.getCache(userDetails.get("userName"));

          cache.clear();
          cache.put("sessionToken", cookieValue);

          return new SimpleAccount(user.getName(), null, this.NAME);
        }
      } catch (CrowdSessionException e) {
        LOG.trace(
          "Crowd session not found with token {}",
            e.getToken()
        );
        return null;
      } catch (CrowdApiException e) {
        LOG.error(
        "Crowd API call failed: {}",
        e.getMessage()
        );
        return null;
      } catch (NotFoundException e) {
        LOG.error("Role not found: {}", e.getMessage());
        return null;
      } catch (ValidationException e) {
        LOG.error("Validation failed {}", e.toString());
        return null;
      } catch (IOException e) {
        LOG.error("I/O error: {}", e.getMessage());
        return null;
      }
    }
  }

  @Override
  public void onLogout(PrincipalCollection principals) {
    super.onLogout(principals);

    final CrowdAuthConfig config = clusterConfigService.getOrDefault(
    CrowdAuthConfig.class,
    CrowdAuthConfig.defaultConfig());

    final CrowdApi crowdApi = new CrowdApi(
    config.apiUrl(),
    config.applicationName(),
    config.applicationPassword(),
    config.apiVerifyCert()
    );

    Collection realmPrincipals = principals.fromRealm(this.NAME);

    for (Object principal : realmPrincipals) {
      CacheManager CacheManager = getCacheManager();
      Cache<String, String> cache = CacheManager.getCache((String)principal);
      String sessionToken = cache.get("sessionToken");

      cache.clear();

      try {
        crowdApi.deleteSession(sessionToken);
      } catch (Exception e) {
        LOG.error(
          "Failed deleting Crowd session {}",
            e.getMessage()
        );
      }
    }
  }

  private String getCookieValue(MultivaluedMap<String, String> headers, String cookieName) {
    if (headers.containsKey("cookie")) {
      for (String cookie : headers.get("cookie")) {
        if (cookie.startsWith(cookieName)) {
          return cookie.split("=")[1].split(";")[0];
        }
      }
    }

    return null;
  }
}
