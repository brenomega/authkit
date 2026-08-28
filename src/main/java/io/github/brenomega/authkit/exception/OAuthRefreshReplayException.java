package io.github.brenomega.authkit.exception;
/** Indicates OAuth refresh reuse after its family has been durably marked compromised. */
public class OAuthRefreshReplayException extends OAuthProtocolException{
 public OAuthRefreshReplayException(){super("invalid_grant","Refresh token reuse detected; token family revoked");}
}
