# Spring Boot 2.2.5 Oauth2 Authentication Server and Client Application

This repository contains the Oauth2 authentication server implementation and its client application. This explains how to build the Oauth2 authentication server in spring boot 2.2.5. 

This repository contains three maven project. 
* my-cloud-service: Its main module, it contains the dependecy management of our application.
* identity-service: This authentication server service. 
* client-application-service: This client application for authentication server.

### Creating the identity-service

You need to add oauth2 dependency for authentication server. 

```xml
<dependency>
   <groupId>org.springframework.security.oauth</groupId>
   <artifactId>spring-security-oauth2</artifactId>
   <version>2.3.3.RELEASE</version>
</dependency>
```

update the application.properties file with below properties.

```properties
logging.level.org.springframework=DEBUG

server.port=8081
server.servlet.context-path=/auth

user.oauth.clientId=my-cloud-identity
user.oauth.clientSecret=VkZpzzKa3uMq4vqg
user.oauth.redirectUris=http://localhost:8082/login/oauth2/code/
user.oauth.user.username=mycloud
user.oauth.user.password=mycloud@1234
```

```client id, client secreate and redirect uris``` are used in the ```AuthorizationServerConfigurerAdapter``` configuration class. ```cliend id and client secreate``` are used in the Oauth2 client configuration. This ```redirect URIs``` is using to redirect and share the autherization code for the client application. ```Username and password``` are using for login the autherization server.

Update the ```IdentityServiceApplication``` class to add ```@EnableResourceServer```:

```java
package com.developerhelperhub.ms.id;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
@EnableResourceServer
public class IdentityServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(IdentityServiceApplication.class, args);
	}

}
```

Create new claas ```AuthorizationServerConfig``` to configure the oauth autherization server. We are configuring the client information of oauth2 autherization in memroy of the applciation. 

```java
package com.developerhelperhub.ms.id.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Value("${user.oauth.clientId}")
	private String clientID;
	@Value("${user.oauth.clientSecret}")
	private String clientSecret;
	@Value("${user.oauth.redirectUris}")
	private String redirectURLs;

	private final PasswordEncoder passwordEncoder;

	public AuthorizationServerConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Spring Security OAuth exposes two endpoints for checking tokens
	 * (/oauth/check_token and /oauth/token_key). Those endpoints are not exposed by
	 * default (have access "denyAll()").
	 */
	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient(clientID).secret(passwordEncoder.encode(clientSecret))
				.authorizedGrantTypes("authorization_code").scopes("user_info").autoApprove(true)
				.redirectUris(redirectURLs);
	}
}

```

We need to create another class for web security which is ```WebSecurity```. This class contains the configuration of url fiteration, authentication, login configurations. The user information also we are configurating in memory of the application. 

```java
package com.developerhelperhub.ms.id.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@Order(1)
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Value("${user.oauth.user.username}")
	private String username;
	@Value("${user.oauth.user.password}")
	private String password;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers("/login", "/oauth/authorize").and().authorizeRequests().anyRequest()
				.authenticated().and().formLogin().permitAll();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(username).password(passwordEncoder().encode(password)).roles("USER");
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
```

Lastly, create a Java class called ```UserController```:

```java
package com.developerhelperhub.ms.id.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@GetMapping("/user/me")
	public Principal user(Principal principal) {
		return principal;
	}
}
```

Above all classes creation we can run the spring boot application, this application run on 8081 and the context path will ```/auth```. We can use this url ```http://localhost:8081/auth/login``` to check, whether it is working or not.

### client-application-service

We need to create the Oauth2 client spring boot application. 

Rename the src/main/resources/application.properties to application.yml and update it to match the YAML below:

```yaml
server:
  port: 8082
  servlet:
    session:
      cookie:
        name: UISESSION

logging:
  level:
    org:
      springframework: DEBUG

spring:
  thymeleaf:
    cache: false
  security:
    oauth2:
      client:
        registration:
          custom-client:
            client-id: my-cloud-identity
            client-secret: VkZpzzKa3uMq4vqg
            client-name: Auth Server
            scope: user_info
            provider: custom-provider
            redirect-uri: http://localhost:8082/login/oauth2/code/
            client-authentication-method: basic
            authorization-grant-type: authorization_code
        provider:
          custom-provider:
            token-uri: http://localhost:8081/auth/oauth/token
            authorization-uri: http://localhost:8081/auth/oauth/authorize
            user-info-uri: http://localhost:8081/auth/user/me
            user-name-attribute: name
```

Notice that here you’re configuring the clientId and clientSecret, as well as various URIs for your authentication server. These need to match the values in the other project.

Update the ```ClientServiceApplication``` class to match:
```java
package com.developerhelperhub.ms.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ClientServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientServiceApplication.class, args);
	}

}
```

Create a new Java class called ```WebController```:
```java
package com.developerhelperhub.ms.client.controller;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class WebController {

	@RequestMapping("/securedPage")
	public String securedPage(Model model, Principal principal) {
		
		model.addAttribute("authenticationName", principal.getName());
        
		return "securedPage";
	}

	@RequestMapping("/")
	public String index(Model model, Principal principal) {
		return "index";
	}
}

```


