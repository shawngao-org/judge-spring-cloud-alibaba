package ltd.sgtu.judge.auth.service.impl;

import ltd.sgtu.judge.auth.mapper.UserMapper;
import ltd.sgtu.judge.auth.entity.User;
import ltd.sgtu.judge.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userService")
public class IUserService implements UserService {

    private UserMapper userMapper;

    @Autowired
    public void setUserMapper(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Override
    public List<User> findAll() {
        return this.userMapper.findAll();
    }

    @Override
    public <T> User getById(T id) {
        return this.userMapper.getById(id);
    }

    @Override
    public User getByEmail(String email) {
        return this.userMapper.getByEmail(email);
    }
}
