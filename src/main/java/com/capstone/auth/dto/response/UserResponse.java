package com.capstone.auth.dto.response;

import lombok.*;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    private Long id;

    private String username;

    private String role;

    boolean locked;
    int failedLoginAttempts;
}
