/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.solr.security;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.invoke.MethodHandles;
import java.security.Principal;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import com.google.common.collect.ImmutableSet;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.auth.BasicUserPrincipal;
import org.apache.http.message.BasicHeader;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.util.ValidatingJsonMap;
import org.apache.solr.common.util.CommandOperation;
import org.apache.solr.common.SpecProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicAuthPlugin extends AuthenticationPlugin implements ConfigEditablePlugin , SpecProvider {
  private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
  private AuthenticationProvider authenticationProvider;
  private final static ThreadLocal<Header> authHeader = new ThreadLocal<>();
  private boolean blockUnknown = false;
  public static final String LDAP_URL = "ldapURL";
  public static final String LDAP_BASE = "ldapBase";
  public static final String LDAP_OBJECT_CLASS = "ldapObjectClass";
  private String ldapURL="ldap://localhost:10389/";
  private String ldapBase="";
  private String ldapObjectClass="";
  public static final String INITIAL_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  public static final String SECURITY_AUTHENTICATION = "simple";

  public boolean ldapAuthentication(String uid, String pwd){
    Hashtable env = new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY, INITIAL_CONTEXT_FACTORY);
    env.put(Context.PROVIDER_URL, ldapURL);
    env.put(Context.SECURITY_AUTHENTICATION, SECURITY_AUTHENTICATION);
    
    DirContext ctx = null;

    boolean success = false;
    log.debug("ldap Authentication");
    try {            
        // Step 1: Bind anonymously            
        ctx = new InitialDirContext(env);

        // Step 2: Search the directory
        String base = ldapBase;
        String filter = "(&(objectClass="+ldapObjectClass+")(uid={0}))";           
        SearchControls ctls = new SearchControls();
        ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ctls.setReturningAttributes(new String[0]);
        ctls.setReturningObjFlag(true);
        NamingEnumeration enm = ctx.search(base, filter, new String[] { uid }, ctls);

        String dn = null;

        if (enm.hasMore()) {
            SearchResult result = (SearchResult) enm.next();
            dn = result.getNameInNamespace();

            //System.out.println("dn: "+dn);
            log.debug("dn: "+dn);
        }

        if (dn == null || enm.hasMore()) {
          // uid not found or not unique
          success = false;
          throw new NamingException("Authentication failed");
        }

        // Step 3: Bind with found DN and given password
        ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, dn);
        ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, pwd);
        // Perform a lookup in order to force a bind operation with JNDI
        ctx.lookup(dn);
        log.debug("Authentication successful");
        
        success = true;
        enm.close();
    } catch (NamingException e) {
      log.debug(e.getMessage());
    } finally {
        try {
          ctx.close();
          return success;
        } catch (NamingException e) {
          //throw new RuntimeException(e);
        }
    }
    return false;
  }
  public boolean authenticate(String username, String pwd) {
    /* changes for ldap starts here */
    //return authenticationProvider.authenticate(username, pwd);
    
    boolean pass = authenticationProvider.authenticate(username, pwd);
    
    if (!pass) {
      //try ldap authentication
      return ldapAuthentication(username, pwd);
    }
    log.debug("success:"+pass);
    return pass;
    /*changes for ldap ends here*/
  }

  @Override
  public void init(Map<String, Object> pluginConfig) {
    Object o = pluginConfig.get(BLOCK_UNKNOWN);
    if (o != null) {
      try {
        blockUnknown = Boolean.parseBoolean(o.toString());
      } catch (Exception e) {
        log.error(e.getMessage());
      }
    }
    Object o1 = pluginConfig.get(LDAP_URL);
    if (o1 != null) {
      try {
        ldapURL = o1.toString();
      } catch (Exception e) {
        log.error(e.getMessage());
      }
    }
    Object o2 = pluginConfig.get(LDAP_BASE);
    if (o2 != null) {
      try {
        ldapBase = o2.toString();
      } catch (Exception e) {
        log.error(e.getMessage());
      }
    }
    Object o3 = pluginConfig.get(LDAP_OBJECT_CLASS);
    if (o3 != null) {
      try {
        ldapObjectClass = o3.toString();
      } catch (Exception e) {
        log.error(e.getMessage());
      }
    }
    authenticationProvider = getAuthenticationProvider(pluginConfig);
  }

  @Override
  public Map<String, Object> edit(Map<String, Object> latestConf, List<CommandOperation> commands) {
    for (CommandOperation command : commands) {
      if (command.name.equals("set-property")) {
        for (Map.Entry<String, Object> e : command.getDataMap().entrySet()) {
          if (PROPS.contains(e.getKey())) {
            latestConf.put(e.getKey(), e.getValue());
            return latestConf;
          } else {
            command.addError("Unknown property " + e.getKey());
          }
        }
      }
    }
    if (!CommandOperation.captureErrors(commands).isEmpty()) return null;
    if (authenticationProvider instanceof ConfigEditablePlugin) {
      ConfigEditablePlugin editablePlugin = (ConfigEditablePlugin) authenticationProvider;
      return editablePlugin.edit(latestConf, commands);
    }
    throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "This cannot be edited");
  }

  protected AuthenticationProvider getAuthenticationProvider(Map<String, Object> pluginConfig) {
    Sha256AuthenticationProvider provider = new Sha256AuthenticationProvider();
    provider.init(pluginConfig);
    return provider;
  }

  private void authenticationFailure(HttpServletResponse response, String message) throws IOException {
    for (Map.Entry<String, String> entry : authenticationProvider.getPromptHeaders().entrySet()) {
      response.setHeader(entry.getKey(), entry.getValue());
    }
    response.sendError(401, message);
  }

  @Override
  public boolean doAuthenticate(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws Exception {

    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    String authHeader = request.getHeader("Authorization");
    if (authHeader != null) {
      BasicAuthPlugin.authHeader.set(new BasicHeader("Authorization", authHeader));
      StringTokenizer st = new StringTokenizer(authHeader);
      if (st.hasMoreTokens()) {
        String basic = st.nextToken();
        if (basic.equalsIgnoreCase("Basic")) {
          try {
            String credentials = new String(Base64.decodeBase64(st.nextToken()), "UTF-8");
            int p = credentials.indexOf(":");
            if (p != -1) {
              final String username = credentials.substring(0, p).trim();
              String pwd = credentials.substring(p + 1).trim();
              if (!authenticate(username, pwd)) {
                log.debug("Bad auth credentials supplied in Authorization header");
                authenticationFailure(response, "Bad credentials");
              } else {
                HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request) {
                  @Override
                  public Principal getUserPrincipal() {
                    return new BasicUserPrincipal(username);
                  }
                };
                filterChain.doFilter(wrapper, response);
                return true;
              }

            } else {
              authenticationFailure(response, "Invalid authentication token");
            }
          } catch (UnsupportedEncodingException e) {
            throw new Error("Couldn't retrieve authentication", e);
          }
        }
      }
    } else {
      if (blockUnknown) {
        authenticationFailure(response, "require authentication");
      } else {
        request.setAttribute(AuthenticationPlugin.class.getName(), authenticationProvider.getPromptHeaders());
        filterChain.doFilter(request, response);
        return true;
      }
    }
    return false;
  }

  @Override
  public void close() throws IOException {

  }

  @Override
  public void closeRequest() {
    authHeader.remove();
  }

  public interface AuthenticationProvider extends SpecProvider {
    void init(Map<String, Object> pluginConfig);

    boolean authenticate(String user, String pwd);

    Map<String, String> getPromptHeaders();
  }

  @Override
  public ValidatingJsonMap getSpec() {
    return authenticationProvider.getSpec();
  }
  public boolean getBlockUnknown(){
    return blockUnknown;
  }

  public static final String BLOCK_UNKNOWN = "blockUnknown";
  private static final Set<String> PROPS = ImmutableSet.of(BLOCK_UNKNOWN);


}
