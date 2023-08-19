package org.goldenrabbit.springbootdeveloper.domain;


import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Entity
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false)
    private Long id;
    @Column(name = "email", nullable = false, unique = true)
    private String email;
    @Column(name = "password")
    private String password;

    @Builder
    public User(String email, String password, String auth) {
        this.email = email;
        this.password = password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 사용자가 가지고 있는 권한의 목록을 반환
        return List.of(new SimpleGrantedAuthority("user"));
    }

    @Override
    public String getUsername() {
        // 사용자를 식별할 수 있는 사용자 이름을 반환
        return email;
    }

    @Override
    public String getPassword() {
        // 사용자의 비밀번호를 반환 이 때 비밀번호는 암호화해서 저장해야 함
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        // 계정이 만료되었는지 확인하는 메서드
        return true; // true -> 만료되지 않았음
    }

    @Override
    public boolean isAccountNonLocked() {
        // 계정이 잠금되었는지 확인하는 메서드
        return true; // true -> 잠금되지 않았음
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // 비밀번호가 만료되었는지 확인하는 메서드
        return true; // true -> 만료되지 않았음
    }

    @Override
    public boolean isEnabled() {
        // 계정이 사용 가능한지 확인하는 메서드
        return true; // true -> 사용 가능
    }

}
