package telran.java47.security.model;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.Getter;
import telran.java47.ENUMS.Roles;

public class User implements Principal {
    String userName;
    @Getter
    Set<Roles> roles;

    public User(String userName, Set<String> roles) {
        this.userName = userName;
        this.roles = roles.stream()
                .map(Roles::valueOf)
                .collect(Collectors.toSet());
    }

    @Override
    public String getName() {
        return userName;
    }
}
