package com.example.mutualauthserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RestController
public class MutualAuthServerApplication extends WebSecurityConfigurerAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(MutualAuthServerApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(MutualAuthServerApplication.class, args);
    }


    /**
     * This will configure the X509AuthenticationFilter, and will authenticate any requests where the provided certificate
     * is included in the trust store, or the certificate has been signed by a CA which is included in the truststore
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
    }

    /**
     * Ignore security for the /headers endpoint.
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/headers", "actuator/**");
    }


    /**
     * Creates a user service, which will provide authorization to users with CN=client
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return (String username) -> {
            if (username.equals("client")) {
                LOG.debug("MutualAuthApp: trying to find a user for: " + username);
                return new User(username, "",
                        AuthorityUtils
                                .commaSeparatedStringToAuthorityList("ROLE_USER"));
            }
            return null;
        };
    }


    /**
     * Spits out information about the client certificate used to authenticate with this app
     * @param principal
     * @return
     */
    @GetMapping("/")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String user(Principal principal) {
        Authentication auth = (Authentication) principal;
        LOG.debug("MutualAuthApp is {} " , auth);
        return String.valueOf(auth.getCredentials());
    }

    /**
     * This http endpoint spits out all of the headers
     * When running on PCF and if the go routers are configured to pass the cert through to the
     * app instance, we should see the header X-Forwarded-Client-Cert.
     * @param request
     * @return
     */
    @GetMapping("/headers")
    public Map<String, String> headers(HttpServletRequest request) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.put(headerName, request.getHeader(headerName));
        }
        return headers;
    }

}
