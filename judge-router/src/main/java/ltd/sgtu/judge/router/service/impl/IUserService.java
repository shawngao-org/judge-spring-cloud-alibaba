package ltd.sgtu.judge.router.service.impl;

import ltd.sgtu.judge.router.entity.User;
import ltd.sgtu.judge.router.mapper.UserMapper;
import ltd.sgtu.judge.router.service.UserService;
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
}
