package com.genjwtrsa.poc.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Classe principale pour activer la sécurité au sein du projet
 *
 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public WebSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		.cors()
		.and()
		.csrf().disable()
		.sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				
		.and().authorizeRequests(configurer -> configurer.antMatchers("/login").permitAll()
		.anyRequest().authenticated())
		.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); //dire que la sécurité est basée sur la vérification du jwt
	}
	
	// mock du user qu'on veut utiliser pour générer le jwt
	@Bean
	@Override
	protected UserDetailsService userDetailsService() {
	   UserDetails user = User
	         .withUsername("kemissi_n")
	         .authorities("FRAMEWORK, USINE-LOGICIELLE")
	         .passwordEncoder(passwordEncoder::encode)
	         .password("1234")
	         .accountExpired(false) // normalement récupéré depuis la bdd
	         .accountLocked(false) // kifkif
	         .credentialsExpired(false) // kifkif
	         .build();
	   
	   InMemoryUserDetailsManager inMemoryUser = new InMemoryUserDetailsManager();
	   inMemoryUser.createUser(user);
	   return inMemoryUser;
	}
	
}
