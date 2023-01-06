package com.genjwtrsa.poc.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.genjwtrsa.poc.configuration.JwtBuilder;
import com.genjwtrsa.poc.dao.SuccessfulResponse;

@RestController
public class AuthenticationController {

	private final JwtBuilder jwtHelper;
	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;

	@Autowired
	public AuthenticationController(JwtBuilder jwtHelper, UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		this.jwtHelper = jwtHelper;
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@PostMapping(path = "/login", consumes = { MediaType.APPLICATION_FORM_URLENCODED_VALUE })
	public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {

		UserDetails userDetails;
		try {
			userDetails = userDetailsService.loadUserByUsername(username); // récupérer le user chargé en mémoire
		} catch (UsernameNotFoundException e) {
			return new ResponseEntity<String>("User inexistant !", HttpStatus.UNAUTHORIZED);
		}

		// pour info : BCRYPT est unidirectionnel, il chiffre mais ne déchiffre pas pour
		// des raisons de sécurité
		if (passwordEncoder.matches(password, userDetails.getPassword())) {
			Map<String, String> claims = new HashMap<>();
			claims.put("username", username);

			String authorities = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
					.collect(Collectors.joining(","));
			claims.put("authorities", authorities);
			claims.put("userId", String.valueOf(1));
			claims.put("id_derogation", "fdhsfjhdsjkhfkdjsh");

			String jwt = jwtHelper.createJwtForClaims(username, claims); // création du jeton jwt
			return new ResponseEntity<SuccessfulResponse>(new SuccessfulResponse(jwt), HttpStatus.OK);
		}
		return new ResponseEntity<String>("Mot de passe invalide, oust !", HttpStatus.UNAUTHORIZED);
	}
}
