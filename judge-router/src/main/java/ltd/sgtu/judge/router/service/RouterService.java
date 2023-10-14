package ltd.sgtu.judge.router.service;

import ltd.sgtu.judge.router.entity.Router;
import ltd.sgtu.judge.router.entity.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface RouterService {

    List<Router> findAll();

    <T> Router getById(T id);
}
