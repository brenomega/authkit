package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RedisTokenStorageScanParserTest {

    @Test
    @DisplayName("HSCAN parser accepts flat RESP field/value pairs")
    void parseHashScanResponse_acceptsFlatPairs() {
        var result = RedisTokenStorage.parseHashScanResponse(List.of(
                bytes("19"),
                List.of(bytes("jti-a"), bytes("hash-a"), bytes("jti-b"), bytes("hash-b"))));

        assertEquals("19", result.nextCursor());
        assertEquals(List.of("jti-a", "jti-b"), result.fields());
    }

    @Test
    @DisplayName("HSCAN parser accepts array-based RESP pairs")
    void parseHashScanResponse_acceptsArrayPairs() {
        Object[] raw = new Object[] {
                bytes("0"),
                new Object[] {bytes("jti-c"), bytes("hash-c")}
        };

        var result = RedisTokenStorage.parseHashScanResponse(raw);

        assertEquals("0", result.nextCursor());
        assertEquals(List.of("jti-c"), result.fields());
    }

    @Test
    @DisplayName("HSCAN parser accepts entry-shaped values returned by Redis clients")
    void parseHashScanResponse_acceptsEntryObjects() {
        var result = RedisTokenStorage.parseHashScanResponse(List.of(
                "7",
                List.of(
                        new AbstractMap.SimpleEntry<>(bytes("jti-d"), bytes("hash-d")),
                        new AbstractMap.SimpleEntry<>(bytes("jti-e"), bytes("hash-e")))));

        assertEquals("7", result.nextCursor());
        assertEquals(List.of("jti-d", "jti-e"), result.fields());
    }

    @Test
    @DisplayName("HSCAN parser accepts cursor-like map scan objects")
    void parseHashScanResponse_acceptsCursorLikeObjects() {
        var result = RedisTokenStorage.parseHashScanResponse(new CursorLike(
                "11",
                Map.of(ByteBuffer.wrap(bytes("jti-f")), bytes("hash-f"))));

        assertEquals("11", result.nextCursor());
        assertEquals(List.of("jti-f"), result.fields());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static final class CursorLike {

        private final String cursor;
        private final Map<Object, Object> map;

        CursorLike(String cursor, Map<Object, Object> map) {
            this.cursor = cursor;
            this.map = map;
        }

        public String getCursor() {
            return cursor;
        }

        public Map<Object, Object> getMap() {
            return map;
        }
    }
}
