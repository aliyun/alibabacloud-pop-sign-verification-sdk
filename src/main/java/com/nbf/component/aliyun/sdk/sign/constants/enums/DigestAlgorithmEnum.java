package com.nbf.component.aliyun.sdk.sign.constants.enums;

/**
 * 签名算法
 *
 * @author 倚枭
 * @date 2021/06/15
 */
public enum DigestAlgorithmEnum {

    /**
     * SHA算法
     */
    SHA_256("SHA-256");

    private final String value;

    DigestAlgorithmEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
