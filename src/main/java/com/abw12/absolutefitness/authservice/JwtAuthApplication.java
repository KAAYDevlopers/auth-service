package com.abw12.absolutefitness.authservice;

import com.abw12.absolutefitness.authservice.exceptions.UnauthorizedException;
import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
//import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

@SpringBootApplication
@RestController
public class JwtAuthApplication {

	@Value("${auth0.domain}")
	private String domain;

	@Value("${auth0.audience}")
	private String audience;

	private JwkProvider jwkProvider;

	@PostConstruct
	public void init() throws MalformedURLException {
		this.jwkProvider = new JwkProviderBuilder(new URL("https://" + domain + "/.well-known/jwks.json"))
				.cached(10, 24, TimeUnit.HOURS)
				.rateLimited(10, 1, TimeUnit.MINUTES)
				.build();
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthApplication.class, args);
	}

	@GetMapping("/auth")
	public String authenticate(@RequestHeader("Authorization") String authorizationHeader) throws RuntimeException {
		try {
			String token = authorizationHeader.replace("Bearer ", "");
			DecodedJWT jwt = JWT.decode(token);

			RSAPublicKey publicKey = (RSAPublicKey) jwkProvider.get(jwt.getKeyId()).getPublicKey();
			Algorithm algorithm = Algorithm.RSA256(publicKey, null);

			JWTVerifier verifier = JWT.require(algorithm)
					.withIssuer("https://" + domain + "/")
					.withAudience(audience)
					.build();

			verifier.verify(jwt);
			return "Authorized"; // Token is valid

		} catch (JWTVerificationException exception){
			// Token is invalid
			throw new UnauthorizedException();
		} catch (JwkException e) {
            throw new RuntimeException(e);
        }
    }
}
