package com.nbf.component.aliyun.sdk.sign;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import com.nbf.component.aliyun.sdk.sign.constants.SignHttpHeaderConstants;
import com.nbf.component.aliyun.sdk.sign.constants.SignSymbolConstants;
import com.nbf.component.aliyun.sdk.sign.constants.enums.DigestAlgorithmEnum;
import com.nbf.component.aliyun.sdk.sign.constants.enums.HmacAlgorithmEnum;
import com.nbf.component.aliyun.sdk.sign.constants.enums.SignProtocolEnum;

/**
 * pop网关后端http签名校验
 *
 * @author 倚枭
 * created on 2021/06/15
 */
public class PopSignValidator {

    /**
     * 安全秘钥，调用前需要先设置
     */
    private static Map<String, String> akSkMap = new HashMap<>(4);

    private static final ThreadLocal<MessageDigest> LOCAL_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    });
    private static final ThreadLocal<Mac> LOCAL_HMAC = ThreadLocal.withInitial(() -> {
        try {
            return Mac.getInstance(HmacAlgorithmEnum.HMAC_SHA_256.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    });

    /**
     * 设置安全秘钥
     * @param accessKeyId
     */
    public static void addAccessKey(String accessKeyId, String accessKeySecret) {
        if (accessKeyId == null || accessKeySecret == null) {
            throw new RuntimeException("参数为空");
        }
        akSkMap.put(accessKeyId, accessKeySecret);
    }

    /**
     * 清空安全秘钥
     */
    public static void clearAccessKey() {
        akSkMap.clear();
    }

    /**
     * 验证签名
     * @param request
     */
    public static void validateSignature(HttpServletRequest request) {
        if (request == null) {
            throw new RuntimeException("param: request is null");
        }
        if (akSkMap.isEmpty()) {
            throw new RuntimeException("accessKeyId / accessKeySecret have not been set");
        }

        String authorization = request.getHeader(SignHttpHeaderConstants.AUTHORIZATION).trim();
        String acs3HmacSha256 = SignProtocolEnum.ACS3_HMAC_SHA256.getValue();
        String[] elementsArr = authorization.substring(
            authorization.indexOf(acs3HmacSha256) + acs3HmacSha256.length() + 1).split(SignSymbolConstants.COMMA);
        HashMap<String, String> signingElements = new HashMap<>(4);
        for (String element : elementsArr) {
            String[] arr = element.split(SignSymbolConstants.EQUAL, -1);
            signingElements.put(arr[0].trim(), arr[1].trim());
        }
        // 待验证，credential和accessKeyId一致
        String credential = signingElements.get(SignHttpHeaderConstants.AUTH_CREDENTIAL);
        String accessKeySecret = akSkMap.get(credential);
        if (accessKeySecret == null) {
            throw new RuntimeException("invalid accessKeyId=" + credential);
        }
        String signedHeaders = signingElements.get(SignHttpHeaderConstants.AUTH_SIGNED_HEADERS);
        if (signedHeaders == null) {
            signedHeaders = SignSymbolConstants.EMPTY;
        }
        String clientSignature = signingElements.get(SignHttpHeaderConstants.AUTH_SIGNATURE);

        String canonicalRequest = buildCanonicalRequest(request, signedHeaders);
        String stringToSign = generateStringToSign(canonicalRequest);
        String serverSign = doSign(stringToSign, accessKeySecret);
        if (!serverSign.equals(clientSignature)) {
            throw new RuntimeException("SignValidateFail. serverStringToSign=[" + stringToSign + "], "
                + "serverCanonicalRequest=[" + canonicalRequest + "]");
        }
    }

    private static String generateStringToSign(String canonicalRequest) {
        return SignProtocolEnum.ACS3_HMAC_SHA256.getValue() + SignSymbolConstants.LINE_SEPARATOR + hexEncodedHash(
            canonicalRequest.getBytes(StandardCharsets.UTF_8));
    }

    private static String doSign(String stringToSign, String accessKeySecret) {
        Mac mac = LOCAL_HMAC.get();
        mac.reset();
        try {
            byte[] secret = accessKeySecret.getBytes(StandardCharsets.UTF_8);
            mac.init(new SecretKeySpec(secret, HmacAlgorithmEnum.HMAC_SHA_256.getValue()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return encodeHex(mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 构造规范化签名串
     *
     * @param request       HttpServletRequest
     * @param signedHeaders 已签名请求头字符串
     */
    private static String buildCanonicalRequest(HttpServletRequest request, String signedHeaders) {
        return request.getMethod().toUpperCase()
            + SignSymbolConstants.LINE_SEPARATOR
            + getCanonicalUri(request.getRequestURI())
            + SignSymbolConstants.LINE_SEPARATOR
            + getCanonicalQueryString(request.getQueryString())
            + SignSymbolConstants.LINE_SEPARATOR
            + getCanonicalHeaders(request, signedHeaders)
            + SignSymbolConstants.LINE_SEPARATOR
            + signedHeaders
            + SignSymbolConstants.LINE_SEPARATOR
            + request.getHeader(SignHttpHeaderConstants.X_ACS_CONTENT_SHA256);
    }

    private static String getCanonicalQueryString(String queryString) {
        if (isBlank(queryString)) {
            return SignSymbolConstants.EMPTY;
        }
        //从queryString中解码出原始参数
        Map<String, List<String>> queryParams = new HashMap<>();
        Jetty9UrlEncodedCopy.decodeUtf8To(queryString, queryParams);

        //将原始参数按签名规则编码和排序
        SortedMap<String, List<String>> sortedEncodedParams = new TreeMap<>();
        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
            String encodedParamName = percentEncodeParam(entry.getKey());
            List<String> paramValues = entry.getValue();
            List<String> encodedValues = new ArrayList<>(paramValues.size());
            paramValues.forEach(
                (value) -> encodedValues.add(value == null ? SignSymbolConstants.EMPTY : percentEncodeParam(value)));
            //有同名参数时按编码后的参数值排序
            if (encodedValues.size() > 1) {
                Collections.sort(encodedValues);
            }
            sortedEncodedParams.put(encodedParamName, encodedValues);
        }
        //构造规范化查询字符串
        StringBuilder result = new StringBuilder();
        sortedEncodedParams.forEach((key, values) -> {
            values.forEach(value -> {
                if (result.length() > 0) {
                    result.append(SignSymbolConstants.AMPERSAND);
                }
                result.append(key);
                if (value != null) {
                    result.append(SignSymbolConstants.EQUAL);
                    result.append(value);
                }
            });
        });
        return result.toString();
    }

    private static String getCanonicalUri(String requestUri) {
        if (isBlank(requestUri)) {
            return SignSymbolConstants.SLASH;
        }
        try {
            return percentEncodeUri(URLDecoder.decode(requestUri, StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 构造规范化请求头
     *
     * @param signedHeaders 已签名消息头列表
     */
    private static String getCanonicalHeaders(HttpServletRequest request, String signedHeaders) {
        if (isBlank(signedHeaders)) {
            return SignSymbolConstants.EMPTY;
        }
        String[] signedHeaderList = signedHeaders.split(SignSymbolConstants.SEMICOLON);
        StringBuilder result = new StringBuilder();
        for (String headerName : signedHeaderList) {
            //headerName取自signedHeaders已经是小写的格式了
            result.append(headerName).append(SignSymbolConstants.COLON);
            Enumeration<String> headerValueEnum = request.getHeaders(headerName);
            if (headerValueEnum != null && headerValueEnum.hasMoreElements()) {
                String headerValue = headerValueEnum.nextElement().trim();
                if (headerValueEnum.hasMoreElements()) {
                    List<String> values = new ArrayList<>(4);
                    values.add(headerValue);
                    do {
                        values.add(headerValueEnum.nextElement().trim());
                    } while (headerValueEnum.hasMoreElements());
                    //对于相同header(不区分大小写)存在多个值的情况，对多个值进行排序
                    Collections.sort(values);
                    result.append(String.join(SignSymbolConstants.COMMA, values));
                } else {
                    result.append(headerValue);
                }
            }
            result.append(SignSymbolConstants.LINE_SEPARATOR);
        }
        return result.toString();
    }

    private static String hexEncodedHash(byte[] input) {
        MessageDigest md = LOCAL_DIGEST.get();
        md.reset();
        md.update(input);
        return encodeHex(md.digest());
    }

    private static final char[] DIGITS_LOWER =
        {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static String encodeHex(final byte[] data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return new String(out);
    }

    private static String percentEncodeParam(String param) {
        try {
            return URLEncoder.encode(param, StandardCharsets.UTF_8.name())
                .replace(SignSymbolConstants.PLUS, "%20")
                .replace(SignSymbolConstants.ASTERISK, "%2A")
                .replace("%7E", SignSymbolConstants.TILDE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String percentEncodeUri(String uri) {
        return percentEncodeParam(uri).replace("%2F", SignSymbolConstants.SLASH);
    }

    private static boolean isBlank(String str) {
        int strLen = str == null ? 0 : str.length();
        if (strLen != 0) {
            for (int i = 0; i < strLen; ++i) {
                if (!Character.isWhitespace(str.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }
}