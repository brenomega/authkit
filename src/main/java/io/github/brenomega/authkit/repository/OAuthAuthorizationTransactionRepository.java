package io.github.brenomega.authkit.repository;
import java.time.Instant;import java.util.*;import org.springframework.data.jpa.repository.*;import org.springframework.data.repository.query.Param;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationTransaction;
public interface OAuthAuthorizationTransactionRepository extends JpaRepository<OAuthAuthorizationTransaction,UUID>{
 Optional<OAuthAuthorizationTransaction> findByTokenHash(String tokenHash);
 @Modifying(clearAutomatically=true,flushAutomatically=true)
 @Query("update OAuthAuthorizationTransaction t set t.consumedAt=:now where t.id=:id and t.consumedAt is null and t.expiresAt>:now")
 int consume(@Param("id")UUID id,@Param("now")Instant now);
 @Modifying @Query("delete from OAuthAuthorizationTransaction t where t.expiresAt<:now")
 int deleteExpired(@Param("now")Instant now);
}
