package com.auth0.samples.authapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SpringBootApplication
@EnableResourceServer
public class Application {
	
	public static class OResourceServer extends ResourceServerConfigurerAdapter{
		@Bean
	    public AuthenticationManager authenticationManager() {
	        final OAuth2AuthenticationManager oAuth2AuthenticationManager = new OAuth2AuthenticationManager();
	        oAuth2AuthenticationManager.setTokenServices(defaultTokenServices());
	        return oAuth2AuthenticationManager;
	    }

	    @Override
	    public void configure(ResourceServerSecurityConfigurer resources)
	            throws Exception {
	        resources.tokenServices(defaultTokenServices()).authenticationManager(
	                authenticationManager());
	        resources.resourceId("887174581528-jup6nprs4kv7qdnjmk0i3mh3b38ui4qn.apps.googleusercontent.com");
	    }

	    @Override
	    public void configure(HttpSecurity http) throws Exception {
	        http.authorizeRequests().antMatchers("/**")
	                .access("hasRole('ROLE_USER')").and()
	                .sessionManagement()
	                .sessionCreationPolicy(SessionCreationPolicy.NEVER);
	    }

	    @Bean
	    public JwtTokenStore tokenStore() {
	        return new JwtTokenStore(tokenEnhancer());
	    }

	    @Bean
	    public JwtAccessTokenConverter tokenEnhancer() {
	        final JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
	        jwtAccessTokenConverter.setVerifier(new MacSigner("MaYzkSjmkzPC57L"));
	        return jwtAccessTokenConverter;
	    }

	    @Bean
	    public ResourceServerTokenServices defaultTokenServices() {
	        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
	        defaultTokenServices.setTokenEnhancer(tokenEnhancer());
	        defaultTokenServices.setTokenStore(tokenStore());
	        return defaultTokenServices;
	    }
	    
	   
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}
