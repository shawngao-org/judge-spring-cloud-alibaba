package ltd.sgtu.judge.router.entity;

import cn.hutool.json.JSONUtil;
import lombok.Data;

import java.io.Serializable;

@Data
public class User implements Serializable {
    private static final long serialVersionUID = -91969758749726312L;
    private Integer id;
    private String name;
    private String password;
    private String email;
    private boolean tfa;
    private String tfaKey;
    private Integer role;

    @Override
    public String toString() {
        return JSONUtil.toJsonStr(this);
    }
}
