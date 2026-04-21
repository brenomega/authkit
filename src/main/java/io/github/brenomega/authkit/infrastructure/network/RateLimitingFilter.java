package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.time.Duration;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter mapping Bucket4j hybrid limitations to the extracted network boundary (DT 3.2.21).
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final NetworkIPResolver ipResolver;
    
    // DT 3.2.21 - Local memory cache bounds blocking micro-burst logic unconditionally 
    private final Cache<String, Bucket> localBuckets;

    public RateLimitingFilter(NetworkIPResolver ipResolver) {
        this.ipResolver = ipResolver;
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterAccess(Duration.ofHours(1))
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Resolve priority IP natively matching the proxy layout (DT 3.2.17)
        String clientIp = ipResolver.resolveClientIp(request);

        // DT 3.2.21 - Acquire local burst bucket. In a native distributed context,
        // this Bucket object would be initialized via Bucket4j JCache/Lettuce ProxyManagers mapping to Redis.
        Bucket bucket = localBuckets.get(clientIp, key -> createNewBucket());

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(429); // 429 Too Many Requests
            response.getWriter().write("Too Many Requests");
        }
    }

    private Bucket createNewBucket() {
        // Enforce 10 requests per minute logic simulating hybrid integration states
        Bandwidth limit = Bandwidth.builder().capacity(10).refillGreedy(10, Duration.ofMinutes(1)).build();
        return Bucket.builder().addLimit(limit).build();
    }
}
