package com.capstone.auth.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import nl.basjes.parse.useragent.UserAgentAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger =
            LoggerFactory.getLogger(RequestLoggingFilter.class);



    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        long startTime = System.currentTimeMillis();

        String method = request.getMethod();
        String uri = request.getRequestURI();
        String clientIp = request.getRemoteAddr();
        String deviceId = request.getHeader("X-Device-Id");
        String userAgent = request.getHeader("User-Agent");


        logger.info(
                "REQUEST | method={} | uri={} | clientIp={} | deviceId={} | userAgent={}",
                method,
                uri,
                clientIp,
                deviceId,
                userAgent
        );

        try {

            filterChain.doFilter(request, response);

        } finally {

            long executionTime =
                    System.currentTimeMillis() - startTime;

            logger.info(
                    "RESPONSE | method={} | uri={} | status={} | time={}ms",
                    method,
                    uri,
                    response.getStatus(),
                    executionTime
            );
        }
    }
}