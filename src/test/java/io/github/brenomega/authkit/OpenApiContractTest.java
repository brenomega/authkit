package io.github.brenomega.authkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;

@SpringBootTest
@ActiveProfiles("test")
class OpenApiContractTest {

    @Autowired
    @Qualifier("requestMappingHandlerMapping")
    private RequestMappingHandlerMapping handlerMapping;

    @Test
    void specificationIsValidAndCoversEveryControllerOperation() {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        var result = new OpenAPIV3Parser().readLocation(
                Path.of("docs/openapi.yaml").toAbsolutePath().toString(), null, options);
        assertTrue(result.getMessages() == null || result.getMessages().isEmpty(),
                () -> "OpenAPI parser messages: " + result.getMessages());
        assertNotNull(result.getOpenAPI());

        Set<String> documented = new HashSet<>();
        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperationsMap()
                .forEach((method, operation) -> documented.add(method.name() + " " + path)));

        Set<String> implemented = new HashSet<>();
        handlerMapping.getHandlerMethods().forEach((mapping, handler) -> {
            Package handlerPackage = handler.getBeanType().getPackage();
            if (handlerPackage == null
                    || !handlerPackage.getName().equals("io.github.brenomega.authkit.controller")) {
                return;
            }
            for (String path : mapping.getPatternValues()) {
                if (path.startsWith("/api/v1/internal/")) {
                    continue;
                }
                for (RequestMethod method : mapping.getMethodsCondition().getMethods()) {
                    implemented.add(method.name() + " " + path);
                }
            }
        });

        assertEquals(implemented, documented);
    }
}
