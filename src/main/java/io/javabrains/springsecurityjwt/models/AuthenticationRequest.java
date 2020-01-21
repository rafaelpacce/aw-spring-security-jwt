package io.javabrains.springsecurityjwt.models;

public class AuthenticationRequest {

    private String keyPublic;
	private String keyPrivate;
    private String oAuthBasePath;
    private String clientId;
    private String userId;
    
    private String jwt;
    
    public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

	public String getKeyPublic() {
		return keyPublic;
	}

	public void setKeyPublic(String keyPublic) {
		this.keyPublic = keyPublic;
	}

	public String getKeyPrivate() {
		return keyPrivate;
	}

	public void setKeyPrivate(String keyPrivate) {
		this.keyPrivate = keyPrivate;
	}

	public String getoAuthBasePath() {
		return oAuthBasePath;
	}

	public void setoAuthBasePath(String oAuthBasePath) {
		this.oAuthBasePath = oAuthBasePath;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}


    //need default constructor for JSON Parsing
    public AuthenticationRequest()
    {

    }

    public AuthenticationRequest(String keyPublic, String keyPrivate, String oAuthBasePath, String clientId,
    		String userId) {
    	super();
    	this.keyPublic = keyPublic;
    	this.keyPrivate = keyPrivate;
    	this.oAuthBasePath = oAuthBasePath;
    	this.clientId = clientId;
    	this.userId = userId;
    }
    
}
