package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.time.Duration;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import org.springframework.lang.NonNull;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.context.annotation.Lazy;
import io.lettuce.core.RedisClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.Advised;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter mapping Bucket4j hybrid limitations to the extracted network boundary (DT 3.2.21).
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);
    private final NetworkIPResolver ipResolver;
    
    // DT 3.2.21 - Local memory cache bounds blocking micro-burst logic unconditionally 
    private final Cache<String, Bucket> localBuckets;
    
    // DT 3.2.21 - Global Redis map backing consistency across horizontal load-balancers
    private volatile ProxyManager<byte[]> proxyManager;

    private final RedisConnectionFactory redisConnectionFactory;

    public RateLimitingFilter(NetworkIPResolver ipResolver, @Lazy RedisConnectionFactory redisConnectionFactory) {
        this.ipResolver = ipResolver;
        this.redisConnectionFactory = redisConnectionFactory;
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterAccess(Duration.ofHours(1))
                .build();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Resolve priority IP natively matching the proxy layout (DT 3.2.17)
        String clientIp = ipResolver.resolveClientIp(request);

        // DT 3.2.21 - Acquire local burst bucket (Layer 1).
        Bucket localBucket = localBuckets.get(clientIp, key -> createNewLayer1Bucket());

        // Validate layer 2 initialization manually upon first access to unpack the Lazy factory cleanly
        if (proxyManager == null) {
            initializeProxyManagerGracefully();
        }

        if (!localBucket.tryConsume(1)) {
            response.setStatus(429); // 429 Too Many Requests
            response.getWriter().write("Too Many Requests");
            return;
        }

        // DT 3.2.21 - Acquire global Redis cluster bucket (Layer 2).
        if (proxyManager != null) {
            try {
                BucketConfiguration configuration = BucketConfiguration.builder()
                        .addLimit(Bandwidth.builder().capacity(50).refillGreedy(50, Duration.ofMinutes(1)).build())
                        .build();

                Bucket globalBucket = proxyManager.builder().build(clientIp.getBytes(), () -> configuration);
                
                if (!globalBucket.tryConsume(1)) {
                    response.setStatus(429);
                    response.getWriter().write("Too Many Requests");
                    return;
                }
            } catch (Exception e) {
                // Fail-open logic DT 3.2.21 & DT 3.1.18: if Redis is unavailable, maintain availability relying on Layer 1 Caffeine
                log.error("Redis proxy exhaustion or failure. Degrading gracefully to local limits. Error: {}", e.getMessage());
            }
        }
        
        filterChain.doFilter(request, response);
    }

    private Bucket createNewLayer1Bucket() {
        // Enforce 10 requests per minute logic simulating hybrid integration states
        Bandwidth limit = Bandwidth.builder().capacity(10).refillGreedy(10, Duration.ofMinutes(1)).build();
        return Bucket.builder().addLimit(limit).build();
    }

    /**
     * Attempts to initialize the ProxyManager thread-safely using Double-Checked Locking (DT 3.2.21, DT 3.1.23).
     */
    private void initializeProxyManagerGracefully() {
        if (proxyManager == null) {
            synchronized (this) {
                if (proxyManager == null) {
                    try {
                        log.info("Attempting to initialize LettuceBasedProxyManager (Self-Healing)...");
                        
                        Object targetFactory = redisConnectionFactory;
                        if (targetFactory instanceof Advised advised) {
                            targetFactory = advised.getTargetSource().getTarget();
                        }

                        if (targetFactory instanceof LettuceConnectionFactory lettuceConnectionFactory) {
                            Object nativeClient = lettuceConnectionFactory.getNativeClient();
                            if (nativeClient instanceof RedisClient redisClient) {
                                this.proxyManager = LettuceBasedProxyManager.builderFor(redisClient).build();
                                log.info("Successfully initialized LettuceBasedProxyManager.");
                            } else {
                                log.error("Initialization failed: native client is not a RedisClient instance.");
                            }
                        } else {
                            log.error("Initialization failed: RedisConnectionFactory is not an instance of LettuceConnectionFactory.");
                        }
                    } catch (Exception e) {
                        // Maintain proxyManager as null to allow clean fail-open to Caffeine (DT 3.2.21).
                        log.error("Resilient initialization attempt failed. System will fail-open to local cache. Error: {}", e.getMessage());
                    }
                }
            }
        }
    }
}
