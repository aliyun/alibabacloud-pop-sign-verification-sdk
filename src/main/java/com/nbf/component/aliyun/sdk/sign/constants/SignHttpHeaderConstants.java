package com.nbf.component.aliyun.sdk.sign.constants;

/**
 * @author 倚枭
 * @date 2021/06/15
 */
public class SignHttpHeaderConstants {

    /**
     * 用于表示请求正文摘要值的http消息头名称
     */
    public static final String X_ACS_CONTENT_SHA256 = "x-acs-content-sha256";
    /**
     * 携带请求认证、签名信息的http消息头名称
     */
    public static final String AUTHORIZATION = "Authorization";
    /**
     * Authorization请求头中表示「已签名消息头列表」的元素
     */
    public static final String AUTH_SIGNED_HEADERS = "SignedHeaders";
    /**
     * Authorization请求头中表示「身份凭证」的元素，这里的身份凭证即为云产品在pop注册的签名秘钥的名称
     */
    public static final String AUTH_CREDENTIAL = "Credential";
    /**
     * Authorization请求头中表示「网关侧签名」的元素
     */
    public static final String AUTH_SIGNATURE = "Signature";
}
