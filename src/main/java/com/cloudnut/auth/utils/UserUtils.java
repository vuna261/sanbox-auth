package com.cloudnut.auth.utils;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserUtils {
    private UserUtils() {}

    public static String ROLE_ADMIN = "ADMIN";
    public static String ROLE_TRAINER = "TRAINER";


    public enum ROLE {
        ADMIN("ROLE_ADMIN"),
        TRAINER("ROLE_TRAINER"),
        TRAINEE("ROLE_TRAINEE");

        private static final Map<String, ROLE> BY_CODE = new HashMap<>();

        public final String grantName;

        ROLE(String grantName) {
            this.grantName = grantName;
        }

        static {
            for (ROLE e : values()) {
                BY_CODE.put(e.grantName, e);
            }
        }

        public static ROLE getByGrant(String grantName) {
            return BY_CODE.get(grantName);
        }

        public String grantType() {
            return this.grantName;
        }
    }

    /**
     * build authority list from role assign
     * @param role
     * @return
     */
    public static List<GrantedAuthority> buildAuthorityByRole(ROLE role) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        switch (role) {
            case ADMIN:
                authorities.add(new SimpleGrantedAuthority(ROLE.ADMIN.grantName));
                authorities.add(new SimpleGrantedAuthority(ROLE.TRAINER.grantName));
                authorities.add(new SimpleGrantedAuthority(ROLE.TRAINEE.grantName));
                break;
            case TRAINER:
                authorities.add(new SimpleGrantedAuthority(ROLE.TRAINER.grantName));
                authorities.add(new SimpleGrantedAuthority(ROLE.TRAINEE.grantName));
                break;
            default:
                authorities.add(new SimpleGrantedAuthority(ROLE.TRAINEE.grantName));
                break;
        }
        return authorities;
    }
}
