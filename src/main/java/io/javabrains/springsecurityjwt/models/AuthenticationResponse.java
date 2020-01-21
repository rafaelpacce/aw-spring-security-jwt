package io.javabrains.springsecurityjwt.models;

public class AuthenticationResponse {

    //private final String jwt;
    private final String access_token;
    private final String token_type;
    private final String expires_in;

    public String getAccess_token() {
		return access_token;
	}


	public String getToken_type() {
		return token_type;
	}

	public String getExpires_in() {
		return expires_in;
	}

	public AuthenticationResponse(String access_token, String token_type, String expires_in) {
		super();
		this.access_token = access_token;
		this.token_type = token_type;
		this.expires_in = expires_in;
	}
//	public AuthenticationResponse(String jwt) {
//        this.jwt = jwt;
//    }
//
//    public String getJwt() {
//        return jwt;
//    }
}
