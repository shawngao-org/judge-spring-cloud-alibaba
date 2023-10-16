package ltd.sgtu.judge.auth.mapper;

import ltd.sgtu.judge.auth.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface UserMapper {

    List<User> findAll();

    <T> User getById(T id);

    User getByEmail(String email);
}
