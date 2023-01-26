package com.sspirng.sspring.configures;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        jdbcDao.setEnableAuthorities(false);
        jdbcDao.setEnableGroups(true);
        jdbcDao.setUsersByUsernameQuery(
                "SELECT " +
                        "login_id, passwd, true " +
                        "FROM " +
                        "USERS " +
                        "WHERE " +
                        "login_id = ?"
        );
        jdbcDao.setGroupAuthoritiesByUsernameQuery(
                "SELECT " +
                        "u.login_id, g.name, p.name " +
                        "FROM " +
                        "users u JOIN groups g ON u.group_id = g.id " +
                        "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
                        "JOIN permissions p ON p.id = gp.permission_id " +
                        "WHERE " +
                        "u.login_id = ?"
        );
        return jdbcDao;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UFT-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                    .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
                    .and()
                .formLogin()
                    .defaultSuccessUrl("/")
                    .permitAll()
                    .and()
                /**
                 * Basic Authentication 설정
                 */
                .httpBasic()
                    .and()
                /**
                 * remember me 설정
                 */
                .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
                /**
                 * 로그아웃 설정
                 */
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true);
        return http.build();
    }

    @Bean
    public ServletWebServerFactory servletContainer() {
        // Enable SSL Trafic
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };

        // Add HTTP to HTTPS redirect
        tomcat.addAdditionalTomcatConnectors(httpToHttpsRedirectConnector());

        return tomcat;
    }

    /*
    We need to redirect from HTTP to HTTPS. Without SSL, this application used
    port 8082. With SSL it will use port 8443. So, any request for 8082 needs to be
    redirected to HTTPS on 8443.
     */
    private Connector httpToHttpsRedirectConnector() {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("http");
        connector.setPort(8080);
        connector.setSecure(false);
        connector.setRedirectPort(443);
        return connector;
    }
}
