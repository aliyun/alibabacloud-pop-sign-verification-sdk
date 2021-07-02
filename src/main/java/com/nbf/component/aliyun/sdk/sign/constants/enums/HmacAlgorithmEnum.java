package com.nbf.component.aliyun.sdk.sign.constants.enums;

/**
 * @author 倚枭
 * @date 2021/06/15
 */
public enum HmacAlgorithmEnum {

    /**
     * hmac sha 256
     */
    HMAC_SHA_256("HmacSHA256");

    private final String value;

    HmacAlgorithmEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
