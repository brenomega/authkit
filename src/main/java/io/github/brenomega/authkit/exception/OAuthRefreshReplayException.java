package io.github.brenomega.authkit.exception;
public class OAuthRefreshReplayException extends OAuthProtocolException{
 public OAuthRefreshReplayException(){super("invalid_grant","Refresh token reuse detected; token family revoked");}
}
