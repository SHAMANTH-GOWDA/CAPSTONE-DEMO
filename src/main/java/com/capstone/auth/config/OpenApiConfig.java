package com.capstone.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI customOpenApiConfig() {
        return new OpenAPI()
                .info(new Info()
                        .title("Authentication API")
                        .version("1.0")
                        .description("Authentication and Serive Implementation for Logging process API")
        );
    }

}