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
import java.util.Arrays;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonProperty;

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
import io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialCallbackResponse;
import io.github.brenomega.authkit.domain.user.dto.AdminUserPageResponse;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;

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
        assertTrue(!result.getOpenAPI().getPaths().containsKey("/api/v1/oauth2/authorize"));
        assertClientAuthenticationAlternatives(result.getOpenAPI(), "/oauth2/token", true);
        assertClientAuthenticationAlternatives(result.getOpenAPI(), "/oauth2/revoke", true);
        assertClientAuthenticationAlternatives(result.getOpenAPI(), "/oauth2/introspect", false);
        result.getOpenAPI().getPaths().forEach((path, item) -> {
            if (path.startsWith("/api/v1/admin/")) item.readOperations().forEach(operation ->
                    assertNotNull(operation.getResponses().get("403"), () -> "Missing admin authorization/step-up failure: " + path));
        });
        for (String schemaName : List.of("EmailChangeRequest", "MfaTotpConfirmRequest", "MfaVerificationRequest")) {
            Schema<?> schema = result.getOpenAPI().getComponents().getSchemas().get(schemaName);
            assertTrue(schema.getRequired() == null || !schema.getRequired().contains("currentPassword"),
                    () -> schemaName + " must permit passwordless fresh-passkey step-up");
            assertEquals(Boolean.TRUE, ((Schema<?>) schema.getProperties().get("currentPassword")).getNullable());
        }

        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperations().forEach(operation ->
                assertTrue(operation.getResponses() != null && !operation.getResponses().isEmpty(),
                        () -> "Operation without documented responses: " + path)));

        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperations().forEach(operation -> {
            var effectiveSecurity = operation.getSecurity() == null
                    ? result.getOpenAPI().getSecurity() : operation.getSecurity();
            if (effectiveSecurity != null && !effectiveSecurity.isEmpty()) {
                assertNotNull(operation.getResponses().get("401"),
                        () -> "Secured operation missing authentication failure: " + path);
            }
        }));

        result.getOpenAPI().getPaths().forEach((path, item) -> item.readOperations().forEach(operation ->
                operation.getResponses().forEach((status, response) -> {
                    if (!status.startsWith("2")) {
                        return;
                    }
                    if ("/oauth2/revoke".equals(path) && "200".equals(status)) {
                        assertTrue(response.getContent() == null || response.getContent().isEmpty(),
                                "OAuth revocation must remain an explicit no-body response");
                        assertTrue(response.getDescription().contains("no response body"));
                        return;
                    }
                    assertNotNull(response.getContent(), () -> "2xx response without content: " + path);
                    var json = response.getContent().get("application/json");
                    assertNotNull(json, () -> "2xx response without application/json: " + path);
                    assertNotNull(json.getSchema(), () -> "2xx response without schema: " + path);
                    assertTrue(isSemanticSchema(json.getSchema()),
                            () -> "2xx response has a free-form schema: " + path);
                })));

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
        assertEquals(Boolean.FALSE, ((Schema<?>) apiResponse.getProperties().get("data")).getAdditionalProperties());
        assertRecordShape(result.getOpenAPI(), tokenResponse, OAuthTokenResponse.class);
        assertRecordShape(result.getOpenAPI(), dataSchema(result.getOpenAPI(), "LoginApiResponse"),
                LoginResponse.class);
        assertRecordShape(result.getOpenAPI(), dataSchema(result.getOpenAPI(), "ProfileApiResponse"),
                ProfileResponse.class);
        assertRecordShape(result.getOpenAPI(), dataSchema(result.getOpenAPI(), "SocialCallbackApiResponse"),
                SocialCallbackResponse.class);
        assertRecordShape(result.getOpenAPI(), dataSchema(result.getOpenAPI(), "AdminUserPageApiResponse"),
                AdminUserPageResponse.class);

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

    private void assertClientAuthenticationAlternatives(OpenAPI openApi, String path, boolean allowsPublicClient) {
        var security = openApi.getPaths().get(path).getPost().getSecurity();
        assertNotNull(security);
        assertTrue(security.stream().anyMatch(requirement -> requirement.containsKey("oauthClientBasic")));
        assertEquals(allowsPublicClient, security.stream().anyMatch(java.util.Map::isEmpty),
                () -> "Unexpected public-client authentication contract for " + path);
    }

    private boolean isSemanticSchema(Schema<?> schema) {
        if (schema.get$ref() != null) {
            return true;
        }
        if (schema.getAllOf() != null && !schema.getAllOf().isEmpty()) {
            return schema.getAllOf().stream().allMatch(this::isSemanticSchema);
        }
        if (schema.getOneOf() != null && !schema.getOneOf().isEmpty()) {
            return schema.getOneOf().stream().allMatch(this::isSemanticSchema);
        }
        if ("array".equals(schema.getType())) {
            return schema.getItems() != null && isSemanticSchema(schema.getItems());
        }
        return schema.getType() != null
                && (!"object".equals(schema.getType())
                    || (schema.getProperties() != null && !schema.getProperties().isEmpty()));
    }

    private Schema<?> dataSchema(OpenAPI openApi, String wrapperName) {
        Schema<?> wrapper = openApi.getComponents().getSchemas().get(wrapperName);
        assertNotNull(wrapper, () -> "Missing response wrapper " + wrapperName);
        Schema<?> data = propertySchema(openApi, wrapper, "data").orElse(null);
        assertNotNull(data, () -> "Missing data schema in " + wrapperName);
        return resolveSchema(openApi, data);
    }

    private Optional<Schema<?>> propertySchema(OpenAPI openApi, Schema<?> rawSchema, String property) {
        Schema<?> schema = resolveSchema(openApi, rawSchema);
        if (schema.getProperties() != null && schema.getProperties().get(property) instanceof Schema<?> value) {
            return Optional.of(value);
        }
        if (schema.getAllOf() != null) {
            return schema.getAllOf().stream()
                    .map(part -> propertySchema(openApi, part, property))
                    .flatMap(Optional::stream)
                    .findFirst();
        }
        return Optional.empty();
    }

    private void assertRecordShape(OpenAPI openApi, Schema<?> rawSchema, Class<?> recordType) {
        Schema<?> schema = resolveSchema(openApi, rawSchema);
        assertNotNull(schema.getProperties(), () -> "Schema has no properties for " + recordType.getName());
        Set<String> jsonFields = Arrays.stream(recordType.getRecordComponents())
                .map(component -> {
                    JsonProperty explicit = component.getAnnotation(JsonProperty.class);
                    if (explicit == null) {
                        explicit = component.getAccessor().getAnnotation(JsonProperty.class);
                    }
                    return explicit == null || explicit.value().isBlank()
                            ? component.getName()
                            : explicit.value();
                })
                .collect(Collectors.toSet());
        assertEquals(jsonFields, schema.getProperties().keySet(),
                () -> "OpenAPI fields drifted from " + recordType.getName());
    }

    private Schema<?> resolveSchema(OpenAPI openApi, Schema<?> schema) {
        if (schema.get$ref() == null) {
            return schema;
        }
        return openApi.getComponents().getSchemas().get(
                schema.get$ref().substring(schema.get$ref().lastIndexOf('/') + 1));
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
