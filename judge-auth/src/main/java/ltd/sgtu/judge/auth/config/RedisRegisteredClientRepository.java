package ltd.sgtu.judge.auth.config;

import cn.hutool.json.JSONUtil;
import ltd.sgtu.judge.auth.util.RedisUtil;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import java.util.Set;

/**
 * Redis storage token
 * TODO: this.jsonStr2OAuth2Authorization()
 */
public class RedisRegisteredClientRepository implements OAuth2AuthorizationService {

    private final RedisUtil redisUtil;
    private final static String UNCOMPLETED_PREFIX = "uncompleted-";

    public RedisRegisteredClientRepository(RedisUtil redisUtil) {
        this.redisUtil = redisUtil;
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        return authorizationCode != null && authorizationCode.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesIdToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OidcIdToken> idToken =
                authorization.getToken(OidcIdToken.class);
        return idToken != null && idToken.getToken().getTokenValue().equals(token);
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesState(authorization, token) ||
                    matchesAuthorizationCode(authorization, token) ||
                    matchesAccessToken(authorization, token) ||
                    matchesIdToken(authorization, token) ||
                    matchesRefreshToken(authorization, token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return matchesState(authorization, token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return matchesAuthorizationCode(authorization, token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return matchesAccessToken(authorization, token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            return matchesIdToken(authorization, token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return matchesRefreshToken(authorization, token);
        }
        return false;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            redisUtil.setValue(authorization.getId(), authorization);
        } else {
            redisUtil.setValue(UNCOMPLETED_PREFIX + authorization.getId(), authorization);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            redisUtil.deleteKey(authorization.getId());
        } else {
            redisUtil.deleteKey(UNCOMPLETED_PREFIX + authorization.getId());
        }
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        OAuth2Authorization authorization = (OAuth2Authorization) redisUtil.getValue(id);
        return authorization != null ?
                authorization :
                (OAuth2Authorization) redisUtil.getValue(UNCOMPLETED_PREFIX + id);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        Set<String> keys = redisUtil.keySet();
        for (String k : keys) {
            OAuth2Authorization authorization =
                    jsonStr2OAuth2Authorization(JSONUtil.toJsonStr(redisUtil.getValue(k)));
            if (hasToken(authorization, token, tokenType)) {
                return authorization;
            }
        }
        return null;
    }

    private static OAuth2Authorization jsonStr2OAuth2Authorization(String s) {
        // TODO: OAuth2Authorization deserializer
        // FIXME:
        //  Jackson JSON cannot construct instance of
        //  `org.springframework.security.oauth2.core.AuthorizationGrantType`
        return null;
    }
}
