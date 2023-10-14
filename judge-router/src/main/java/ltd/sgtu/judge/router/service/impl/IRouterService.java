package ltd.sgtu.judge.router.service.impl;

import ltd.sgtu.judge.router.entity.Router;
import ltd.sgtu.judge.router.mapper.RouterMapper;
import ltd.sgtu.judge.router.service.RouterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("routerService")
public class IRouterService implements RouterService {

    @Autowired
    private RouterMapper routerMapper;

    /**
     * @return
     */
    @Override
    public List<Router> findAll() {
        return this.routerMapper.findAll();
    }

    /**
     * *
     * @param id
     * @return
     * @param <T>
     */
    @Override
    public <T> Router getById(T id) {
        return this.routerMapper.getById(id);
    }
}
