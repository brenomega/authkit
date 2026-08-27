package io.github.brenomega.authkit.repository;
import java.util.*;import org.springframework.data.jpa.repository.*;import org.springframework.data.repository.query.Param;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthRefreshToken;
public interface OAuthRefreshTokenRepository extends JpaRepository<OAuthRefreshToken,UUID>{
 @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE) @Query("select t from OAuthRefreshToken t where t.tokenHash=:hash")
 Optional<OAuthRefreshToken> findByTokenHashForUpdate(@Param("hash")String hash);
 Optional<OAuthRefreshToken> findByTokenHash(String hash);
 List<OAuthRefreshToken> findByFamilyId(UUID familyId);
 long deleteByFamilyIdIn(Collection<UUID> familyIds);
 @Modifying @Query("delete from OAuthRefreshToken t where t.expiresAt<:now")
 int deleteExpired(@Param("now")java.time.Instant now);
}
