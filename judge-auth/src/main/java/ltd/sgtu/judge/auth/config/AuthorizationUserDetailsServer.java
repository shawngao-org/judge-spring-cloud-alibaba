package ltd.sgtu.judge.auth.config;

import ltd.sgtu.judge.auth.common.dto.UserDto;
import ltd.sgtu.judge.auth.entity.User;
import ltd.sgtu.judge.auth.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Service
public class AuthorizationUserDetailsServer implements UserDetailsService {

    @Resource
    private UserService userService;

    /**
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getById(1);
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
