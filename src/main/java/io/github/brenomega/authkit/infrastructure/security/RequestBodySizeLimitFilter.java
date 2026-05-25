package io.github.brenomega.authkit.infrastructure.security;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.lang.NonNull;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.response.ApiResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RequestBodySizeLimitFilter extends OncePerRequestFilter {

    private static final int BUFFER_SIZE = 4096;

    private final AuthProperties authProperties;
    private final ObjectMapper objectMapper;

    public RequestBodySizeLimitFilter(AuthProperties authProperties, ObjectMapper objectMapper) {
        this.authProperties = authProperties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        long maxBodyBytes = authProperties.getRequest().getMaxBodyBytes();
        long contentLength = request.getContentLengthLong();

        if (contentLength > maxBodyBytes) {
            writePayloadTooLarge(response);
            return;
        }

        if (!mayHaveRequestBody(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        byte[] body = readBody(request, maxBodyBytes);
        if (body == null) {
            writePayloadTooLarge(response);
            return;
        }

        filterChain.doFilter(new CachedBodyRequest(request, body), response);
    }

    private byte[] readBody(HttpServletRequest request, long maxBodyBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.min(maxBodyBytes, BUFFER_SIZE));
        byte[] buffer = new byte[BUFFER_SIZE];
        long bytesRead = 0;
        int read;

        ServletInputStream inputStream = request.getInputStream();
        while ((read = inputStream.read(buffer)) != -1) {
            bytesRead += read;
            if (bytesRead > maxBodyBytes) {
                return null;
            }
            output.write(buffer, 0, read);
        }

        return output.toByteArray();
    }

    private boolean mayHaveRequestBody(HttpServletRequest request) {
        return "POST".equals(request.getMethod())
                || "PUT".equals(request.getMethod())
                || "PATCH".equals(request.getMethod());
    }

    private void writePayloadTooLarge(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.error("Request body too large"));
    }

    private static class CachedBodyRequest extends HttpServletRequestWrapper {

        private final byte[] body;

        CachedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);

            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                    if (readListener == null) {
                        return;
                    }
                    try {
                        readListener.onDataAvailable();
                        if (isFinished()) {
                            readListener.onAllDataRead();
                        }
                    } catch (IOException ex) {
                        readListener.onError(ex);
                    }
                }

                @Override
                public int read() {
                    return input.read();
                }
            };
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }
}
