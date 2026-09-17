package com.capstone.auth.security;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class RateLimiterFilter implements Filter {

   private final RateLimiterRegistry rateLimiterRegistry;


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        String ipAddress = httpServletRequest.getRemoteAddr();


        RateLimiter rateLimiter = rateLimiterRegistry.rateLimiter(ipAddress,"default");

        try {
            rateLimiter.acquirePermission();
            chain.doFilter(request, response);
        }
        catch (RequestNotPermitted requestNotPermitted) {
            httpServletResponse.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            httpServletResponse.getWriter().write("Request not permitted");
            httpServletResponse.setContentType("application/json");
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
