package ltd.sgtu.judge.router.service;

import ltd.sgtu.judge.router.entity.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {

    List<User> findAll();

    <T> User getById(T id);
}
