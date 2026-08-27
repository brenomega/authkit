package io.github.brenomega.authkit.exception;
import org.springframework.http.HttpStatus;
public class OAuthProtocolException extends InvalidOAuthRequestException{
 private final String error;private final String description;
 public OAuthProtocolException(String error,String description){this.error=error;this.description=description;}
 public String getError(){return error;}public String getDescription(){return description;}public HttpStatus protocolStatus(){return "invalid_client".equals(error)?HttpStatus.UNAUTHORIZED:HttpStatus.BAD_REQUEST;}
}
