package com.dimon.notes.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;
import java.util.List;

@Setter
@Getter
public class UserInfoResponse {
    private Long id;
    private String username;
    private String email;
    private boolean accountNonLocked;
    private boolean accountNonExpired;
    private boolean credentialNonExpired;
    private boolean enabled;
    private LocalDate credentialExpiryDate;
    private LocalDate accountExpiryDate;
    private boolean isTwoFactorEnabled;
    private List<String> roles;

    public UserInfoResponse(Long id, String username, String email, boolean accountNonLocked, boolean accountNonExpired, boolean credentialNonExpired, boolean enabled, LocalDate credentialExpiryDate, LocalDate accountExpiryDate, boolean isTwoFactorEnabled, List<String> roles) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.accountNonLocked = accountNonLocked;
        this.accountNonExpired = accountNonExpired;
        this.credentialNonExpired = credentialNonExpired;
        this.enabled = enabled;
        this.credentialExpiryDate = credentialExpiryDate;
        this.accountExpiryDate = accountExpiryDate;
        this.isTwoFactorEnabled = isTwoFactorEnabled;
        this.roles = roles;
    }


}
