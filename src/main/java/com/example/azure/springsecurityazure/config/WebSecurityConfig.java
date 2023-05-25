package com.example.azure.springsecurityazure.config;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import net.minidev.json.JSONArray;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated().and().oauth2Login().userInfoEndpoint()
                .oidcUserService(this.oidcUserService());
    }

    /**
     * Replaces the granted authorities value received in token with the roles value
     * in token received from the app roles attribute defined in manifest and
     * creates a new OIDCUser with updated mappedAuthorities
     *
     * @return oidcUser
     */
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);
            oidcUser.getAuthorities().forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    Map<String, Object> userInfo = oidcUserAuthority.getAttributes();
                    JSONArray roles = null;
                    if (userInfo.containsKey("roles")) {
                        try {
                            roles = (JSONArray) userInfo.get("roles");
                            roles.forEach(s -> {
                                mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + (String) s));
                            });
                        } catch (Exception e) {
                            // Replace this with logger during implementation
                            e.printStackTrace();
                        }
                    }
                }
            });
            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

            return oidcUser;
        };
    }

}