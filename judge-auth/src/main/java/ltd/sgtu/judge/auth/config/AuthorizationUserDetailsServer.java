package ltd.sgtu.judge.auth.config;

import ltd.sgtu.judge.auth.common.dto.UserDto;
import ltd.sgtu.judge.auth.entity.User;
import ltd.sgtu.judge.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AuthorizationUserDetailsServer implements UserDetailsService {

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        UserDto userDto = new UserDto();
        userDto.setId(String.valueOf(user.getId()));
        userDto.setUsername(user.getEmail());
        userDto.setPassword(user.getPassword());
        userDto.setEmail(user.getEmail());
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("user"));
        userDto.setAuthorities(authorities);
        return userDto;
    }
}
