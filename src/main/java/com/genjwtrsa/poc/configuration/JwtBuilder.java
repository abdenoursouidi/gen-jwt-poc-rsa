package com.genjwtrsa.poc.configuration;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import org.springframework.context.annotation.Configuration;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;

/**
 * Classe pour créer le jeton jwt
 *
 */

@Configuration
public class JwtBuilder {

	private final RSAPrivateKey privateKey;
	private final RSAPublicKey publicKey;
	
	public JwtBuilder(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}
	
	// création du jeton jwt avec les claims
	public String createJwtForClaims(String subject, Map<String, String> claims) {
		Calendar calendar = Calendar.getInstance();
		calendar.setTimeInMillis(Instant.now().toEpochMilli());
		calendar.add(Calendar.HOUR, 1);
		
		JWTCreator.Builder jwtBuilder = JWT.create().withSubject(subject);
		
		// ajour des claims
		claims.forEach(jwtBuilder::withClaim);
		
		return jwtBuilder
				.withNotBefore(new Date()) // quand il a été créé
				.withExpiresAt(calendar.getTime()) // quand il va expirer
				.sign(Algorithm.RSA256(publicKey, privateKey)); // signature du jeton avec RSA
	}
}
