package ltd.sgtu.judge.router.mapper;

import ltd.sgtu.judge.router.entity.Router;
import ltd.sgtu.judge.router.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface RouterMapper {

    List<Router> findAll();

    <T> Router getById(T id);
}
