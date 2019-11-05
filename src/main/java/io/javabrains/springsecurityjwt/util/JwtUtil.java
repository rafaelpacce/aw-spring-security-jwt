package io.javabrains.springsecurityjwt.util;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

@Service
public class JwtUtil {

	public String generateJWTAssertionFromString(String keyPublic, String keyPrivate, String oAuthBasePath,
			String clientId, String userId)
			throws JWTCreationException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {

		final long EXPIRATION_TIME = 3600 * 1000; // 1 hora = 3600
		String token = null;

		if (keyPublic == null || "".equals(keyPublic) || keyPrivate == null || "".equals(keyPrivate)
				|| oAuthBasePath == null || "".equals(oAuthBasePath) || clientId == null || "".equals(clientId)
				|| userId == null || "".equals(userId)) {
			throw new IllegalArgumentException("One of the arguments is null or empty");
		}

		try {

			Date issued = new Date(); // data criação
			Date expires = new Date(System.currentTimeMillis() + EXPIRATION_TIME);

			RSAPublicKey publicKey = readPublicKeyFromString(keyPublic);
			RSAPrivateKey privateKey = readPrivateKeyFromString(keyPrivate);
			Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

			token = JWT.create().withIssuer(clientId).withSubject(userId).withIssuedAt(issued)
					.withAudience(oAuthBasePath).withExpiresAt(expires).withClaim("scope", "signature impersonation")
					.sign(algorithm);
		} catch (JWTCreationException e) {
			throw e;
		}

		return token;
	}

	// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	private static RSAPublicKey readPublicKeyFromString(String publicKeyContent)
			throws InvalidKeySpecException, NoSuchAlgorithmException {

		publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "");
		KeyFactory kf = KeyFactory.getInstance("RSA");

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
		RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

		return pubKey;

	}

	// ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	private static RSAPrivateKey readPrivateKeyFromString(String privateKeyContent)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "");
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory kf = KeyFactory.getInstance("RSA");

		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
		RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);

		return (RSAPrivateKey) privKey;

	}
}