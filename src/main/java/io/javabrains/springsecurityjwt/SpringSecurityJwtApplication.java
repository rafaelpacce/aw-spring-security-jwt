package io.javabrains.springsecurityjwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.models.AuthenticationResponse;
import io.javabrains.springsecurityjwt.util.JwtUtil;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

}

@RequestMapping("jwt/v1")
@RestController
class HelloWorldController {

	@Autowired
	private JwtUtil jwtTokenUtil;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		
		String keyPublic = authenticationRequest.getKeyPublic();
		String keyPrivate = authenticationRequest.getKeyPrivate();		
		String oAuthBasePath = authenticationRequest.getoAuthBasePath();
		String clientId = authenticationRequest.getClientId();
		String userId = authenticationRequest.getUserId();
		
		final String jwt = jwtTokenUtil.generateJWTAssertionFromString(keyPublic, keyPrivate, oAuthBasePath, clientId, userId);

		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

}

