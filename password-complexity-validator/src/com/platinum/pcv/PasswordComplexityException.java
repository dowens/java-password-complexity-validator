package com.platinum.pcv;

/**
 *
 * @author jlucier
 */
public class PasswordComplexityException extends Exception {

	private static final long serialVersionUID = -5310848576449958224L;

	public PasswordComplexityException(String message) {
		super(message);
	}

	public PasswordComplexityException(String message, Throwable cause) {
		super(message, cause);
	}

}

