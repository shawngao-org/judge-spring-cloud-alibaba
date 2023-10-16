package ltd.sgtu.judge.auth.service.impl;

import ltd.sgtu.judge.auth.mapper.UserMapper;
import ltd.sgtu.judge.auth.entity.User;
import ltd.sgtu.judge.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userService")
public class IUserService implements UserService {

    @Autowired
    private UserMapper userMapper;

    /**
     * @return
     */
    @Override
    public List<User> findAll() {
        return this.userMapper.findAll();
    }

    /**
     * *
     * @param id
     * @return
     * @param <T>
     */
    @Override
    public <T> User getById(T id) {
        return this.userMapper.getById(id);
    }

    /**
     * @param email
     * @return
     */
    @Override
    public User getByEmail(String email) {
        return this.userMapper.getByEmail(email);
    }
}
