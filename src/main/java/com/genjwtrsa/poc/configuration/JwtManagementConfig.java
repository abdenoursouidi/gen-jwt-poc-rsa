package com.genjwtrsa.poc.configuration;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * 
 * Classe pour chargé le keystore / clé publique et privée & validation du jeton
 *
 */

@Configuration
public class JwtManagementConfig {

	@Value("${app.security.jwt.keystore-location}")
	private String keyStorePath;

	@Value("${app.security.jwt.keystore-password}")
	private String keyStorePassword;

	@Value("${app.security.jwt.key-alias}")
	private String keyAlias;

	@Value("${app.security.jwt.private-key-passphrase}")
	private String privateKeyPassphrase;

	// récupération du keystore
	@Bean
	public KeyStore keyStore() throws Exception {
		try {
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream resourceAsStream = Thread.currentThread().getContextClassLoader()
					.getResourceAsStream(keyStorePath);
			keyStore.load(resourceAsStream, keyStorePassword.toCharArray());
			return keyStore;
		} catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
			throw new IllegalArgumentException("Impossible de charger le keystore");
		}
	}

	// retourner la clé privée RSA depuis le keystore
	@Bean
	public RSAPrivateKey jwtSigningKey(KeyStore keyStore) throws Exception {
		try {
			Key key = keyStore.getKey(keyAlias, privateKeyPassphrase.toCharArray());
			if (key instanceof RSAPrivateKey) {
				return (RSAPrivateKey) key;
			}
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
			throw new IllegalArgumentException("Impossible de charger la clé privée");
		}

		throw new IllegalArgumentException("Impossible de charger la clé privée");
	}

	// retourner la clé publique RSA depuis le keystore
	@Bean
	public RSAPublicKey jwtValidationKey(KeyStore keyStore) {
		try {
			Certificate certificate = keyStore.getCertificate(keyAlias);
			PublicKey publicKey = certificate.getPublicKey();

			if (publicKey instanceof RSAPublicKey) {
				return (RSAPublicKey) publicKey;
			}
		} catch (KeyStoreException e) {
			throw new IllegalArgumentException("Impossible de charger la clé publique");
		}

		throw new IllegalArgumentException("Impossible de charger la clé publique");
	}

	// bean pour valider le jwt avec la clé publique
	@Bean
	public JwtDecoder jwtDecoder(RSAPublicKey rsaPublicKey) {
		return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
	}

}
