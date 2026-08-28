package io.github.brenomega.authkit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;

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
        options.setResolveFully(true);
        var result = new OpenAPIV3Parser().readLocation(
                Path.of("docs/openapi.yaml").toAbsolutePath().toString(), null, options);
        assertTrue(result.getMessages() == null || result.getMessages().isEmpty(),
                () -> "OpenAPI parser messages: " + result.getMessages());
        assertNotNull(result.getOpenAPI());
        assertNotNull(result.getOpenAPI().getComponents().getSecuritySchemes().get("bearerAuth"));
        assertNotNull(result.getOpenAPI().getComponents().getSecuritySchemes().get("oauthAccessBearer"));
        assertTrue(result.getOpenAPI().getComponents().getSecuritySchemes().get("bearerAuth")
                .getDescription().contains("token_use=first_party_access"));
        assertTrue(result.getOpenAPI().getComponents().getSecuritySchemes().get("oauthAccessBearer")
                .getDescription().contains("token_use=oauth_access"));
        assertTrue(result.getOpenAPI().getPaths()
                .get("/oauth2/userinfo")
                .getGet()
                .getSecurity()
                .stream()
                .anyMatch(requirement -> requirement.containsKey("oauthAccessBearer")));

        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperations().forEach(operation ->
                assertTrue(operation.getResponses() != null && !operation.getResponses().isEmpty(),
                        () -> "Operation without documented responses: " + path)));

        var authorize = result.getOpenAPI().getPaths().get("/oauth2/authorize").getGet();
        assertTrue(authorize.getParameters().stream()
                .filter(parameter -> Set.of(
                    "state",
                    "code_challenge",
                    "code_challenge_method").contains(parameter.getName()))
                .allMatch(parameter -> Boolean.TRUE.equals(parameter.getRequired())));
        assertEquals(List.of("S256"), authorize.getParameters().stream()
                .filter(parameter -> "code_challenge_method".equals(parameter.getName()))
                .findFirst().orElseThrow().getSchema().getEnum());

        var tokenResponse = result.getOpenAPI().getComponents().getSchemas().get("OAuthTokenResponse");
        assertTrue(tokenResponse.getProperties().containsKey("access_token"));
        assertTrue(tokenResponse.getProperties().containsKey("id_token"));
        assertTrue(tokenResponse.getProperties().containsKey("refresh_token"));
        assertTrue(tokenResponse.getProperties().containsKey("token_type"));
        assertTrue(tokenResponse.getProperties().containsKey("expires_in"));
        assertTrue(tokenResponse.getProperties().containsKey("scope"));
        assertEquals(Boolean.FALSE, tokenResponse.getAdditionalProperties());
        var apiResponse = result.getOpenAPI().getComponents().getSchemas().get("ApiResponse");
        assertTrue(apiResponse.getRequired().contains("timestamp"));
        assertTrue(apiResponse.getRequired().contains("requestId"));
        assertTrue(apiResponse.getProperties().containsKey("code"));

        result.getOpenAPI().getComponents().getSchemas().forEach((name, schema) -> {
            if (name.endsWith("Request")) {
                assertEquals(Boolean.FALSE, schema.getAdditionalProperties(),
                        () -> "Input schema must reject unknown fields: " + name);
            }
        });
        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperations().forEach(operation -> {
            var rateLimited = operation.getResponses().get("429");
            if (rateLimited != null) {
                var effective = rateLimited.get$ref() == null ? rateLimited
                        : result.getOpenAPI().getComponents().getResponses().get(
                                rateLimited.get$ref().substring(rateLimited.get$ref().lastIndexOf('/') + 1));
                assertNotNull(effective.getHeaders(), () -> "429 missing headers: " + path);
                assertTrue(effective.getHeaders().containsKey("Retry-After"),
                        () -> "429 missing Retry-After: " + path);
            }
        }));

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
                for (RequestMethod method : mapping.getMethodsCondition().getMethods()) {
                    implemented.add(method.name() + " " + path);
                    Operation operation = operation(result.getOpenAPI().getPaths().get(path), method);
                    assertNotNull(operation, () -> "Missing OpenAPI operation: " + method + " " + path);
                    assertControllerInputsDocumented(result.getOpenAPI(), path, operation, handler);
                }
            }
        });

        assertEquals(implemented, documented);
    }

    private void assertControllerInputsDocumented(OpenAPI openApi, String path, Operation operation,
            org.springframework.web.method.HandlerMethod handler) {
        List<Parameter> parameters = new ArrayList<>();
        if (openApi.getPaths().get(path).getParameters() != null) {
            parameters.addAll(openApi.getPaths().get(path).getParameters());
        }
        if (operation.getParameters() != null) {
            parameters.addAll(operation.getParameters());
        }

        for (var methodParameter : handler.getMethodParameters()) {
            methodParameter.initParameterNameDiscovery(new org.springframework.core.DefaultParameterNameDiscoverer());
            RequestBody jsonBody = methodParameter.getParameterAnnotation(RequestBody.class);
            if (jsonBody != null) {
                var documentedBody = effectiveRequestBody(openApi, operation.getRequestBody());
                assertNotNull(documentedBody,
                        () -> "Missing request body: " + handler.getMethod().toGenericString());
                assertEquals(jsonBody.required(), Boolean.TRUE.equals(documentedBody.getRequired()),
                        () -> "Request-body requiredness mismatch: " + handler.getMethod().toGenericString());
            }

            PathVariable pathVariable = methodParameter.getParameterAnnotation(PathVariable.class);
            if (pathVariable != null) {
                String name = annotationName(
                    pathVariable.name(),
                    pathVariable.value(),
                    methodParameter.getParameterName());
                assertTrue(parameters.stream().anyMatch(parameter ->
                                "path".equals(parameter.getIn()) && name.equals(parameter.getName())
                                        && Boolean.TRUE.equals(parameter.getRequired())),
                        () -> "Missing required path parameter " + name + " for " + path);
            }

            RequestParam query = methodParameter.getParameterAnnotation(RequestParam.class);
            if (query != null) {
                String name = annotationName(query.name(), query.value(), methodParameter.getParameterName());
                boolean queryDocumented = parameters.stream().anyMatch(parameter ->
                        "query".equals(parameter.getIn()) && name.equals(parameter.getName()));
                boolean formDocumented = formSchema(openApi, operation).map(schema ->
                        schema.getProperties() != null && schema.getProperties().containsKey(name)).orElse(false);
                assertTrue(queryDocumented || formDocumented,
                        () -> "Missing query/form parameter " + name + " for " + path);
            }
        }
    }

    private io.swagger.v3.oas.models.parameters.RequestBody effectiveRequestBody(OpenAPI openApi,
            io.swagger.v3.oas.models.parameters.RequestBody body) {
        if (body == null || body.get$ref() == null) {
            return body;
        }
        return openApi.getComponents().getRequestBodies().get(
                body.get$ref().substring(body.get$ref().lastIndexOf('/') + 1));
    }

    private Optional<Schema<?>> formSchema(OpenAPI openApi, Operation operation) {
        var body = effectiveRequestBody(openApi, operation.getRequestBody());
        if (body == null || body.getContent() == null
                || body.getContent().get("application/x-www-form-urlencoded") == null) {
            return Optional.empty();
        }
        Object rawSchema = body.getContent().get("application/x-www-form-urlencoded").getSchema();
        if (!(rawSchema instanceof Schema<?> raw)) {
            return Optional.empty();
        }
        Schema<?> schema = raw;
        if (schema.get$ref() != null) {
            Object resolved = openApi.getComponents().getSchemas().get(
                    schema.get$ref().substring(schema.get$ref().lastIndexOf('/') + 1));
            if (!(resolved instanceof Schema<?> resolvedSchema)) {
                return Optional.empty();
            }
            schema = resolvedSchema;
        }
        return Optional.ofNullable(schema);
    }

    private String annotationName(String name, String value, String parameterName) {
        if (name != null && !name.isBlank()) {
            return name;
        }
        if (value != null && !value.isBlank()) {
            return value;
        }
        return parameterName;
    }

    private Operation operation(PathItem item, RequestMethod method) {
        return switch (method) {
            case GET -> item.getGet();
            case HEAD -> item.getHead();
            case POST -> item.getPost();
            case PUT -> item.getPut();
            case PATCH -> item.getPatch();
            case DELETE -> item.getDelete();
            case OPTIONS -> item.getOptions();
            case TRACE -> item.getTrace();
        };
    }
}
