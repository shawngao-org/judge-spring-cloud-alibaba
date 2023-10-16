package ltd.sgtu.judge.auth.service;

import ltd.sgtu.judge.auth.entity.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {

    List<User> findAll();

    <T> User getById(T id);

    User getByEmail(String email);
}
