## OAuth2 authorization server

### API

+ 授权 /oauth2/consent - GET
  + ```
    http://localhost:25560/oauth2/consent?
    client_id=c1
    &response_type=code
    &scope=all
    &redirect_uri=https://www.baidu.com
    &state=state
    ```

    | 参数             | 必填  | 说明                                               |
    |----------------|-----|--------------------------------------------------|
    | client_id      | Yes | 客户端ID                                            |
    | response_type  | Yes | 响应类型, 固定为code                                    |
    | scope          | Yes | 授权范围, 固定为all                                     |
    | redirect_uri   | Yes | 授权通过/拒绝后回调地址                                     |
    | state          | Yes | 用于防止重放攻击, 开发者可以根据此信息来判断redirect_uri只能执行一次来避免重放攻击 |

+ 登录 /login - GET
