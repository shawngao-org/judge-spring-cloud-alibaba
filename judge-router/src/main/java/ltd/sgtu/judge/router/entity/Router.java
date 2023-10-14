package ltd.sgtu.judge.router.entity;

import lombok.Data;

import java.io.Serializable;

@Data
public class Router implements Serializable {
    private static final long serialVersionUID = -91969758749726312L;
    private int id;
    private String key;
    private String path;
    private String name;
    private Boolean visible;
    private Integer parent;
}
