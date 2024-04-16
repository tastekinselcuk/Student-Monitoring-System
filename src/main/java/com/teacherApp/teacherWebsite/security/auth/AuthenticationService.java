package com.teacherApp.teacherWebsite.security.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.teacherApp.teacherWebsite.model.Token;
import com.teacherApp.teacherWebsite.model.User;
import com.teacherApp.teacherWebsite.model.users.Student;
import com.teacherApp.teacherWebsite.model.users.Tutor;
import com.teacherApp.teacherWebsite.enums.Role;
import com.teacherApp.teacherWebsite.enums.TokenType;
import com.teacherApp.teacherWebsite.exception.AppException;
import com.teacherApp.teacherWebsite.repository.TokenRepository;
import com.teacherApp.teacherWebsite.repository.UserRepository;
import com.teacherApp.teacherWebsite.security.config.JwtService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;



/**
 * Authentication Service
 * 
 * procedures for registration and login are written here
 *
 */
@Log4j2
@Service
@RequiredArgsConstructor
public class AuthenticationService {
	  private final UserRepository repository;
	  private final TokenRepository tokenRepository;
	  private final PasswordEncoder passwordEncoder;
	  private final JwtService jwtService;
	  private final AuthenticationManager authenticationManager;

	  /**
	   * Register service, if applicable save user and return token.
	   *
	   * @param RegisterRequest request - contains name, surname, email, password and role(s).
	   * @return JWT token
	   */
	  public AuthenticationResponse register(RegisterRequest request) {
		    log.trace("registration started");

		    if (repository.existsByEmailAndDeletedFalse(request.getEmail())) {
		        throw new AppException(
		                HttpStatus.BAD_REQUEST,
		                "Email Already Exist",
		                "Provided email already exists!"
		        );
		    }

		    if (request.getPassword().length() < 8 || !request.getPassword().matches(".*[a-z].*") || !request.getPassword().matches(".*[A-Z].*")) {
		        throw new AppException(
		                HttpStatus.BAD_REQUEST,
		                "Invalid Password",
		                "Password should contain at least one lowercase letter, one uppercase letter, and be at least 8 characters long!"
		        );
		    }

		    User user;
		    if (request.getRole() == Role.STUDENT) {
		        user = Student.builder()
		                .firstname(request.getFirstname())
		                .lastname(request.getLastname())
		                .email(request.getEmail())
		                .password(passwordEncoder.encode(request.getPassword()))
		                .role(request.getRole())
		                .deleted(false)
		                .parentName(request.getParentName())
		                .parentLastName(request.getParentLastName())
		                .parentPhoneNumber(request.getParentPhoneNumber())
		                .build();
		    } else if (request.getRole() == Role.TUTOR) {
		        user = Tutor.builder()
		                .firstname(request.getFirstname())
		                .lastname(request.getLastname())
		                .email(request.getEmail())
		                .password(passwordEncoder.encode(request.getPassword()))
		                .role(request.getRole())
		                .deleted(false)
		                .subject(request.getSubject())
		                .build();
		    } else {
		        throw new AppException(
		                HttpStatus.BAD_REQUEST,
		                "Invalid Role",
		                "Invalid user role provided!"
		        );
		    }

		    var savedUser = repository.save(user);
		    var jwtToken = jwtService.generateToken(user);
		    var refreshToken = jwtService.generateRefreshToken(user);
		    saveUserToken(savedUser, jwtToken);

		    log.trace("registration completed for {}", user.getFirstname());

		    return AuthenticationResponse.builder()
		            .accessToken(jwtToken)
		            .refreshToken(refreshToken)
		            .build();
		}


	  /**
	   * Login service, if applicable give permission for login and return token.
	   *
	   * @param AuthenticationRequest request - contains email and password.
	   * @return JWT token
	   */
	  public AuthenticationResponse authenticate(AuthenticationRequest request) {
			log.trace("authentication started");
			
			try {
			    authenticationManager.authenticate(
			            new UsernamePasswordAuthenticationToken(
			                request.getEmail(),
			                request.getPassword()
			            )
			        );
			        var user = repository.findByEmail(request.getEmail())
			            .orElseThrow();
			        var jwtToken = jwtService.generateToken(user);
			        var refreshToken = jwtService.generateRefreshToken(user);
			        revokeAllUserTokens(user);
			        saveUserToken(user, jwtToken);
			    	log.trace("authentication completed for {}", user.getFirstname());
			        return AuthenticationResponse.builder()
			            .accessToken(jwtToken)
			                .refreshToken(refreshToken)
			            .build();
				
			} catch (Exception e) {
		        throw new AppException(
		                HttpStatus.UNAUTHORIZED,
		                "Invalid email or password",
		                "The email or password provided is invalid!"
		        );	}
		    
	  }
  
  /**
   * Saves the user token in the token repository.
   *
   * @param user     User - the user object.
   * @param jwtToken String - the JWT token.
   */
  private void saveUserToken(User user, String jwtToken) {
		log.trace("saving user started");
	    var token = Token.builder()
	        .user(user)
	        .token(jwtToken)
	        .tokenType(TokenType.BEARER)
	        .expired(false)
	        .revoked(false)
	        .build();
	    tokenRepository.save(token);
		log.trace("saving completed for {}", user.getFirstname());

  }

  /**
   * Revokes all tokens associated with the given user.
   *
   * @param user User - the user object.
   */
  private void revokeAllUserTokens(User user) {
	    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
	    if (validUserTokens.isEmpty())
	      return;
	    validUserTokens.forEach(token -> {
	      token.setExpired(true);
	      token.setRevoked(true);
	    });
	    tokenRepository.saveAll(validUserTokens);
  }

  /**
   * Refreshes the access token using the provided refresh token.
   *
   * @param request  HttpServletRequest - the HTTP request object.
   * @param response HttpServletResponse - the HTTP response object.
   * @throws IOException if an I/O error occurs.
   */
  public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail)
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
  
}
