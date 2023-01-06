package com.genjwtrsa.poc.dao;

import org.springframework.lang.NonNull;

/**
 * Réponse sous format json pour le /login
 *
 */

public class SuccessfulResponse {

	@NonNull
	private String jwt;

	public SuccessfulResponse(String jwt) {
		this.jwt = jwt;
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

}
