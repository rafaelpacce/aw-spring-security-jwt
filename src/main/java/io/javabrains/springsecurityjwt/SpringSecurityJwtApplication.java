package io.javabrains.springsecurityjwt;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.util.JwtUtil;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import okhttp3.OkHttpClient;	

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

}

@RequestMapping("/pocs/v1")
@RestController	
class HelloWorldController {
	
	OkHttpClient client = new OkHttpClient();
	
	@Autowired
	private Environment env;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@RequestMapping(value = "/authenticate", produces = "application/json", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity<JSONObject> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		
		String keyPublic = authenticationRequest.getKeyPublic();
		String keyPrivate = authenticationRequest.getKeyPrivate();		
		String oAuthBasePath = authenticationRequest.getoAuthBasePath();
		String clientId = authenticationRequest.getClientId();
		String userId = authenticationRequest.getUserId();
		
		final String jwt = jwtTokenUtil.generateJWTAssertionFromString(keyPublic, keyPrivate, oAuthBasePath, clientId, userId);
		
		//authenticationRequest.setJwt(jwt);		
		//System.out.println(authenticationRequest.getJwt());
		
		String base_url_docusign = env.getProperty("url.dev.docusign");
		String grant_type = env.getProperty("grant.docusign");
		
		HttpResponse<String> response = Unirest.post(base_url_docusign + "/oauth/token").
				header("accept", "application/json").
				header("content-type", "application/json").
			    queryString("assertion", jwt).
			    queryString("grant_type", grant_type).
			    asString();
		
		System.out.println(response.getBody());
		
		JSONParser parser = new JSONParser();
		JSONObject json = (JSONObject) parser.parse(response.getBody());
		
		//return json;

		return ResponseEntity.ok(json);
	}
	
//	
//	@RequestMapping(value = "/oauth/token", method = RequestMethod.POST)
//	public ResponseEntity<?> getAccessToken(@RequestParam("grant_type") String grant_type
//											,@RequestParam("assertion") String assertion
//											/*,@RequestParam("redirect_uri") String redirect_uri*/) throws Exception	{
//		
//		//AuthenticationRequest authenticationRequest = new AuthenticationRequest();
//		
//		String base_url_docusign = env.getProperty("url.dev.docusign");
//		
//		HttpUrl.Builder urlBuilder = HttpUrl.parse(base_url_docusign + "/oauth/token").newBuilder();
//		urlBuilder.addQueryParameter("grant_type", grant_type);
//	    urlBuilder.addQueryParameter("assertion", assertion);
//	    //urlBuilder.addQueryParameter("redirect_uri", redirect_uri);
//	    
//	    System.out.println(urlBuilder);
//	 
//	    String url = urlBuilder.build().toString();	 
//	    
//	    Request request = new Request.Builder().url(url)
//	    		.addHeader("Content-Type", "application/json")
//	    		.build();
//	    
//	    Response response = client.newCall(request).execute();
//	 
//        System.out.println(response);
//	 
//	    return ResponseEntity.ok(response);
//
//		//return ResponseEntity.ok(new AuthenticationResponse(jwt));
//	}
	
	@RequestMapping(value = "/oauth/token", method = RequestMethod.POST)
	public JSONObject getAccessToken(@RequestParam("grant_type") String grant_type
											,@RequestParam("assertion") String assertion
											/*,@RequestParam("redirect_uri") String redirect_uri*/) throws Exception	{
		
		String base_url_docusign = env.getProperty("url.dev.docusign");
		
		HttpResponse<String> response = Unirest.post(base_url_docusign + "/oauth/token").
				header("accept", "application/json").
				header("content-type", "application/json").
			    queryString("assertion", assertion).
			    queryString("grant_type", grant_type).
			    asString();
		
		System.out.println(response.getBody());
		
		JSONParser parser = new JSONParser();
		JSONObject json = (JSONObject) parser.parse(response.getBody());
		
		return json;

		//return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
	
	
	@RequestMapping(value = "/users", method = RequestMethod.GET)
	 public String getUsersUsingUnirest() throws Exception {
		    HttpResponse<String> response = Unirest.get("http://localhost:3000/users").
		        header("Content-Type",  "application/json").
		        asString();
		    System.out.println(response.getBody());
		    //System.out.println(response.getBody().getObject().toString(2));
		    
		    return response.getBody();
		  }

	

}

