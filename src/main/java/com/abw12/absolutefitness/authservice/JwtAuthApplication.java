package com.abw12.absolutefitness.authservice;

import com.abw12.absolutefitness.authservice.dto.AuthRequest;
import com.abw12.absolutefitness.authservice.exceptions.UnauthorizedException;
import com.abw12.absolutefitness.authservice.service.JwtService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.net.MalformedURLException;

@SpringBootApplication
@RestController
public class JwtAuthApplication {

//	@Autowired
//	private AuthenticationManager authenticationManager;
//
//	@Value("${auth0.domain}")
//	private String domain;
//
//	@Value("${auth0.audience}")
//	private String audience;

	@Value("${app_id}")
	private String validAppId;

	@Value("${secret}")
	private String SECRET;


	@Autowired
	private JwtService jwtService;

	// private JwkProvider jwkProvider;

	private static final Logger logger = LoggerFactory.getLogger(JwtAuthApplication.class);

//	@PostConstruct
//	public void init() throws MalformedURLException {
//		logger.info("Inside init method.");
//		URL url = new URL("https://" + domain + "/.well-known/jwks.json");
//		logger.info("the url is {}", url);
//		logger.debug("the url is {}", url);
//		this.jwkProvider = new JwkProviderBuilder(url)
//				.cached(10, 24, TimeUnit.HOURS)
//				.rateLimited(10, 1, TimeUnit.MINUTES)
//				.build();
//	}

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthApplication.class, args);
	}

	@PostMapping("/generateToken")
	private String authenticate(@RequestBody AuthRequest authRequest) throws MalformedURLException {
		if (authRequest.getAppID() != null && isValidAppId(authRequest.getAppID())) {
			String token = jwtService.generateToken(authRequest.getAppID());
			logger.info("token generated successfully");
			logger.debug("token is: {}", token);
			return token;
		}
		throw new MalformedURLException();
    }

	private boolean isValidAppId(String appID) {
		return appID.equalsIgnoreCase(validAppId);
	}

	@GetMapping("/auth")
	public String authenticate(@RequestHeader("Authorization") String authorizationHeader) throws RuntimeException {
		logger.info("Inside validate token");
		try {
			// new validation
			String token = authorizationHeader.replace("Bearer ", "");
			Algorithm algorithm = Algorithm.HMAC256(SECRET); // Use the same secret key as in token generation

			JWTVerifier verifier = JWT.require(algorithm)
					.build();

			verifier.verify(token);
			return "Authorized"; // Token is valid

			// commenting the validation logic for jwt from auth0

//			String token = authorizationHeader.replace("Bearer ", "");
//			DecodedJWT jwt = JWT.decode(token);
//
//			RSAPublicKey publicKey = (RSAPublicKey) jwkProvider.get(jwt.getKeyId()).getPublicKey();
//			Algorithm algorithm = Algorithm.RSA256(publicKey, null);
//
//			JWTVerifier verifier = JWT.require(algorithm)
//					.withIssuer("https://" + domain + "/")
//					.withAudience(audience)
//					.build();
//
//			verifier.verify(jwt);
//			return "Authorized"; // Token is valid

		} catch (JWTVerificationException exception){
			logger.info("Unauthorized error in your auth-service");
			throw new UnauthorizedException();
 		}
    }
}
