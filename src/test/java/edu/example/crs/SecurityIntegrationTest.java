package edu.example.crs;

import java.time.Instant;
import java.util.List;

import edu.example.crs.catalog.Course;
import edu.example.crs.catalog.CourseService;
import edu.example.crs.enrollment.EnrollmentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    private static final String PASSWORD = "fixture-password-21";
    private static final String MOBILE_ORIGIN = "https://mobile.crs.example";
    private static final String COURSES = "/api/courses";
    private static final String ALICE = "/api/students/alice/enrollments";
    private static final String BOB = "/api/students/bob/enrollments";
    private static final String TOKEN = "/api/auth/token";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private JwtDecoder decoder;

    @Autowired
    private JwtEncoder encoder;

    @Autowired
    private UserDetailsService users;

    @Autowired
    private BCryptPasswordEncoder passwords;

    @Autowired
    private CourseService catalog;

    @Autowired
    private EnrollmentService enrollments;

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry properties) {
        var encoder = new BCryptPasswordEncoder();
        for (String user : List.of("alice", "bob", "advisor", "registrar")) {
            String hash = encoder.encode(PASSWORD);
            properties.add("crs.accounts." + user + ".hash", () -> hash);
        }
        properties.add("crs.mobile-origin", () -> MOBILE_ORIGIN);
    }

    @Test
    void anonymousRequestsRequireAuthenticationAcrossTheApi() throws Exception {
        mvc.perform(get(COURSES)).andExpect(status().isUnauthorized());
        mvc.perform(post(COURSES)).andExpect(status().isUnauthorized());
        mvc.perform(get(ALICE)).andExpect(status().isUnauthorized());
        mvc.perform(post(ALICE)).andExpect(status().isUnauthorized());
        mvc.perform(delete(ALICE + "/CS101")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/unmapped")).andExpect(status().isUnauthorized());
        mvc.perform(get(TOKEN)).andExpect(status().isUnauthorized());
    }

    @Test
    void signedJwtAuthenticatesEachRequestWithoutCreatingASession() throws Exception {
        String token = login("alice");
        var claims = decoder.decode(token);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getClaimAsStringList("roles")).containsExactly("STUDENT");
        assertThat(claims.getExpiresAt()).isAfter(Instant.now());

        var request = mvc.perform(get(ALICE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].student").value("alice"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn().getRequest();

        assertThat(request.getSession(false)).isNull();
        mvc.perform(get(ALICE)).andExpect(status().isUnauthorized());
        mvc.perform(get(BOB).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void rejectsBadCredentialsAndInvalidTokens() throws Exception {
        mvc.perform(post(TOKEN).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"alice","password":"incorrect-password"}
                                """))
                .andExpect(status().isUnauthorized());

        String token = login("alice");
        int signatureStart = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart) + replacement + token.substring(signatureStart + 1);
        mvc.perform(get(COURSES).header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized());

        var claims = JwtClaimsSet.builder().issuer("secured-crs").audience(List.of("secured-crs-api"))
                .subject("alice").expiresAt(Instant.now().minusSeconds(120)).build();
        String expired = encoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        mvc.perform(get(COURSES).header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void studentCanReadCatalogAndManageOwnEnrollmentsOnly() throws Exception {
        var alice = bearer("alice");
        mvc.perform(get(COURSES).with(alice)).andExpect(status().isOk());
        mvc.perform(get(COURSES + "/CS101").with(alice)).andExpect(status().isOk());
        mvc.perform(post(COURSES).with(alice).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"CS301","title":"Algorithms"}
                                """))
                .andExpect(status().isForbidden());
        mvc.perform(get(ALICE).with(alice)).andExpect(status().isOk());
        mvc.perform(get(BOB).with(alice)).andExpect(status().isForbidden());
        mvc.perform(addEnrollment(BOB, "CS101").with(alice)).andExpect(status().isForbidden());
        mvc.perform(delete(BOB + "/CS201").with(alice)).andExpect(status().isForbidden());
        addAndDrop(ALICE, "CS201", alice);
    }

    @Test
    void advisorIsBoundedByCaseloadForReadsAndWrites() throws Exception {
        var advisor = bearer("advisor");
        mvc.perform(get(COURSES).with(advisor)).andExpect(status().isOk());
        mvc.perform(post(COURSES).with(advisor).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"CS301","title":"Algorithms"}
                                """))
                .andExpect(status().isForbidden());
        mvc.perform(get(ALICE).with(advisor)).andExpect(status().isOk());
        mvc.perform(get(BOB).with(advisor)).andExpect(status().isForbidden());
        mvc.perform(addEnrollment(BOB, "CS101").with(advisor)).andExpect(status().isForbidden());
        mvc.perform(delete(BOB + "/CS201").with(advisor)).andExpect(status().isForbidden());
        addAndDrop(ALICE, "CS201", advisor);
    }

    @Test
    void registrarJwtAllowsCatalogWritesAndManagementOfBothStudents() throws Exception {
        String authorization = "Bearer " + login("registrar");
        mvc.perform(post(COURSES).header(HttpHeaders.AUTHORIZATION, authorization)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"CS301","title":"Algorithms"}
                                """))
                .andExpect(status().isCreated());

        for (String student : List.of(ALICE, BOB)) {
            mvc.perform(get(student).header(HttpHeaders.AUTHORIZATION, authorization))
                    .andExpect(status().isOk());
            mvc.perform(addEnrollment(student, "CS301").header(HttpHeaders.AUTHORIZATION, authorization))
                    .andExpect(status().isCreated());
            mvc.perform(delete(student + "/CS301").header(HttpHeaders.AUTHORIZATION, authorization))
                    .andExpect(status().isNoContent());
        }
    }

    @Test
    @WithMockUser(username = "alice", roles = "STUDENT")
    void authorizationAlsoAppliesWhenCallingServicesDirectly() {
        assertThatThrownBy(() -> catalog.create(new Course("CS401", "Capstone")))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> enrollments.list("bob")).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> enrollments.add("bob", "CS101")).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> enrollments.drop("bob", "CS201")).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void accountsStoreSaltedBcryptHashes() {
        String alice = users.loadUserByUsername("alice").getPassword();
        String bob = users.loadUserByUsername("bob").getPassword();
        assertThat(alice).startsWith("$2").hasSize(60).isNotEqualTo(bob).isNotEqualTo(PASSWORD);
        assertThat(passwords.matches(PASSWORD, alice)).isTrue();
        assertThat(passwords.matches(PASSWORD, bob)).isTrue();
        assertThat(passwords.matches("wrong", alice)).isFalse();
    }

    @Test
    void corsAllowsOnlyTheConfiguredMobileOrigin() throws Exception {
        mvc.perform(options(ALICE)
                        .header(HttpHeaders.ORIGIN, MOBILE_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization, content-type"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, MOBILE_ORIGIN));

        mvc.perform(options(ALICE)
                        .header(HttpHeaders.ORIGIN, "https://other.example")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name()))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    private String login(String username) throws Exception {
        var response = mvc.perform(post(TOKEN).contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(new Credentials(username, PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();
        assertThat(response.getRequest().getSession(false)).isNull();
        return json.readTree(response.getResponse().getContentAsString()).get("accessToken").asString();
    }

    private RequestPostProcessor bearer(String username) throws Exception {
        String authorization = "Bearer " + login(username);
        return request -> {
            request.addHeader(HttpHeaders.AUTHORIZATION, authorization);
            return request;
        };
    }

    private void addAndDrop(String path, String code, RequestPostProcessor bearer) throws Exception {
        mvc.perform(addEnrollment(path, code).with(bearer)).andExpect(status().isCreated());
        mvc.perform(delete(path + "/" + code).with(bearer)).andExpect(status().isNoContent());
    }

    private MockHttpServletRequestBuilder addEnrollment(
            String path, String code) {
        return post(path).contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"courseCode":"%s"}
                        """.formatted(code));
    }

    private record Credentials(String username, String password) {
    }
}
