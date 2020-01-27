import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import org.cache2k.Cache;
import org.cache2k.Cache2kBuilder;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;

public class JWTValidation {
	
	//Externalize the hosts as per the environment
	final static String jwksHost = ""; 	
	// Create a cache object
	final static Cache<String,String> _cache = new Cache2kBuilder<String, String>() {}
	  .expireAfterWrite(30, TimeUnit.MINUTES)    // expire/refresh after 30 minutes
    .build();	  
	static String _jwkVersionCache = _cache.peek("jwk_version");
	static String _modulusCache = _cache.peek("modulus");
	static String _exponentCache = _cache.peek("exponent");
	
	public static void main(String[] args) throws JsonParseException, JsonMappingException, IOException {	
		System.out.println("Sample code to validate JWT");	
		// Running the code in loop to test multiple scenarios
		while(true) {	
			
			// Used only for console app to get the JWS as user input
			Scanner reader = new Scanner(System.in);
			// Get the JWT 
			System.out.println("Enter jwt or enter exit to terminate");	
			String signedJwtToken = reader.next();

			if(signedJwtToken.equalsIgnoreCase("Exit")) 
			{				
				break;
			}
			
			try {
				// Validate the signed JWT (JWS)
				ValidateJWS(signedJwtToken);
			}
			catch (Exception e) {
				System.out.println("JWS validation failed");
			}
			finally {

			}
		}				
	}	
	
	// Code to validate signed JWT (JWS)
	private static void ValidateJWS(String signedJwtToken)
	{
		StringBuilder sb = null;
		String jwtWithoutSignature;	
		String jwtVersion;
		String jwksUri;
		String jwksUrl;
		String kid;
		TypeReference<Map<String, Object>> typeRef = new TypeReference<Map<String, Object>>() {};
		ObjectMapper mapper = new ObjectMapper();	
		Map<String, Object> jwks = null;
			
		@SuppressWarnings("rawtypes")
		Jwt<Header, Claims> jwtClaims = null;
		try {			
			
			// Extract the base64 encoded JWT from the signed JWT token (JWS) 
			sb = new StringBuilder();
			sb.append(signedJwtToken);
			jwtWithoutSignature = sb.substring(0, sb.toString().lastIndexOf(".") + 1);	
			
			// Parse claims without validating the signature
			jwtClaims = Jwts.parser().parseClaimsJwt(jwtWithoutSignature);	
			
			// Extract the jwk uri 'jku' & the version 'ver' from the JWT	
			jwtVersion = (String) jwtClaims.getBody().get("ver");
			jwksUri = (String) jwtClaims.getBody().get("jku");
			// Extract the kid from JWT
			kid = (String) jwtClaims.getHeader().get("kid");
			
			jwksUrl = jwksHost + jwksUri;
			
            // Cache the jwk version (ver), modulus (n) and exponent (e) for lifetime of the application.
            // The JWT version will be same as jwk version. The jwt version will change only when the 
            // JWT signing certificate is renewed.
            // Invoke the JWK url only if the jwt version is different from the JWK version. 
			
			// check if the JWK version is cached or not
			if (_cache.get("jwk_version") != null) {
				// check if jwt version is same as jwk version 
				if (!jwtVersion.equals(_jwkVersionCache)) {
					// Get the jwk key & add the modulus, exponent & the jwk version to the cache
					GetJWK(jwksUrl, kid);	
				}
			}
            else
            {
                // Get the jwk key & add the modulus, exponent & the jwk version to the cache
            	GetJWK(jwksUrl, kid);		
            }
			
			// Calling the setSigningKeyResolver as the JWT is parsed before validating the signature 
			SigningKeyResolver resolver = new SigningKeyResolverAdapter() {
			    @SuppressWarnings("rawtypes")
				public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
			        try {            
			            // Build the RSA public key from modulus & exponent in JWK 
			            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(_modulusCache));
			            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(_exponentCache));
			            PublicKey rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
			            return rsaPublicKey;
			        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			        	System.out.println("Failed to resolve key: " + e);
			            return null;
			        }
			    }
			};
			
			try {
				// Parse claims and validate the signature
				Jws<Claims> jwsClaims = Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(signedJwtToken);
				System.out.println("Signature on this JWT is good and the JWT token has not expired");
				// OK, we can trust this JWT
				
				// Parse the claims
				System.out.println("JWS claims: " + jwsClaims.getBody());
				
				// Code below to validate the claims
				
			}
			catch (Exception ex) {
				System.out.println("Unable to validate JWS");
			}

		}
		// catch (SignatureException e)
		catch (Exception e) {
			// don't trust the JWT!
			System.out.println("JWT is malformed or expired");
		}					
	}
		
	// Get the corresponding JWK using key Id from the JWK set 
    @SuppressWarnings("unchecked")
    static private Map<String, String> GetKeyById(Map<String, Object> jwks, String kid) {
        List<Map<String, String>> keys = (List<Map<String, String>>)jwks.get("keys");
        Map<String, String> ret = null;
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i).get("kid").equals(kid)) {            	
                return keys.get(i);
            }
        }    
        return ret;
    }
   
    // Get the JWK Set from the JWK endpoint 
    private static void GetJWK(String jwkUrl, String kid) {
        HttpURLConnection connection = null;

        try {
            URL url = new URL(jwkUrl);
            connection = (HttpURLConnection) url.openConnection();
			// Header should be externalized as it will be different for each environment 
			connection.setRequestProperty ("x-ibm-client-secret", "");
			connection.setRequestProperty ("x-ibm-client-id", "");			

            connection.setRequestMethod("GET");

            BufferedReader rd = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');

            }
            rd.close();
            
            // Jackson mapper for parsing the json
    		TypeReference<Map<String, Object>> typeRef = new TypeReference<Map<String, Object>>() {};
    		ObjectMapper mapper = new ObjectMapper();
    		Map<String, Object> jwks = mapper.readValue(response.toString(), typeRef);
        	// Get the jwk by using the key Id from the jwt
            Map<String, String> jwk = GetKeyById(jwks, kid);
            
            // Get the modulus 'n' & the exponent 'n' from the JWK & add it to cache 
            if (jwk != null) {
            	_cache.put("modulus", jwk.get("n"));
            	_modulusCache = _cache.get("modulus");
            	_cache.put("exponent", jwk.get("e"));
            	_exponentCache = _cache.get("exponent");
            	_cache.put("jwk_version", jwk.get("ver"));
            	_jwkVersionCache = _cache.get("jwk_version");
            }            
        } catch (Exception e) {
        	// Unable to fetch JWKS. Terminate this program
        	System.out.println("Error getting jwks: " + e);         	
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
