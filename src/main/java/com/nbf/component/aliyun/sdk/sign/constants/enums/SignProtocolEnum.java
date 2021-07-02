package com.nbf.component.aliyun.sdk.sign.constants.enums;

/**
 * 签名协议枚举
 *
 * @author 倚枭
 * @date 2021/06/15
 */
public enum SignProtocolEnum {

    /**
     * HMAC签名协议
     */
    ACS3_HMAC_SHA256("ACS3-HMAC-SHA256");

    private final String value;

    SignProtocolEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
