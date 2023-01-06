package com.genjwtrsa.poc.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	private final UserDetailsService userDetailsService;

	@Autowired
	public UserController(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	// route protégée, il faut un jeton jwt valide
	@GetMapping("/user")
	public UserDetails getUser(Authentication authentication) {
		JwtAuthenticationToken token = (JwtAuthenticationToken) authentication; // récupération automatique du jeton
		Map<String, Object> attributes = token.getTokenAttributes();
		return userDetailsService.loadUserByUsername(attributes.get("username").toString()); // récupérer les infos du user chargé en mémoire
	}
}
