package com.nbf.component.aliyun.sdk.sign;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author 倚枭
 * created on 2021/06/15
 */
public class Jetty9UrlEncodedCopy {

    public static void decodeUtf8To(String query, Map<String, List<String>> map) {
        Utf8StringBuilder buffer = new Utf8StringBuilder();
        synchronized (map) {
            String key = null;
            String value = null;

            int end = query.length();
            for (int i = 0; i < end; i++) {
                char c = query.charAt(i);
                switch (c) {
                    case '&':
                        value = buffer.toReplacedString();
                        buffer.reset();
                        if (key != null) {
                            addToMap(key, value, map);
                        } else if (value != null && value.length() > 0) {
                            addToMap(value, "", map);
                        }
                        key = null;
                        value = null;
                        break;

                    case '=':
                        if (key != null) {
                            buffer.append(c);
                            break;
                        }
                        key = buffer.toReplacedString();
                        buffer.reset();
                        break;

                    case '+':
                        buffer.append((byte)' ');
                        break;

                    case '%':
                        if (i + 2 < end) {
                            char hi = query.charAt(++i);
                            char lo = query.charAt(++i);
                            buffer.append(decodeHexByte(hi, lo));
                        } else {
                            throw new Utf8StringBuilder.NotUtf8Exception("Incomplete % encoding");
                        }
                        break;

                    default:
                        buffer.append(c);
                        break;
                }
            }

            if (key != null) {
                value = buffer.toReplacedString();
                buffer.reset();
                addToMap(key, value, map);
            } else if (buffer.length() > 0) {
                addToMap(buffer.toReplacedString(), "", map);
            }
        }
    }

    private static void addToMap(String key, String value, Map<String, List<String>> map) {
        List<String> list = map.computeIfAbsent(key, k -> new ArrayList<>());
        list.add(value);
    }

    private static byte decodeHexByte(char hi, char lo) {
        try {
            return (byte)((convertHexDigit(hi) << 4) + convertHexDigit(lo));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Not valid encoding '%" + hi + lo + "'");
        }
    }

    public static int convertHexDigit(char c) {
        int d = ((c & 0x1f) + ((c >> 6) * 0x19) - 0x10);
        if (d < 0 || d > 15) {
            throw new NumberFormatException("!hex " + c);
        }
        return d;
    }

    public static class Utf8StringBuilder {
        // @checkstyle-disable-check : AvoidEscapedUnicodeCharactersCheck
        public static final char REPLACEMENT = '\ufffd';
        public static final byte[] REPLACEMENT_UTF8 = new byte[] {(byte)0xEF, (byte)0xBF, (byte)0xBD};
        private static final int UTF8_ACCEPT = 0;
        private static final int UTF8_REJECT = 12;

        protected final Appendable _appendable;
        protected int _state = UTF8_ACCEPT;

        private static final byte[] BYTE_TABLE =
            {
                // The first part of the table maps bytes to character classes that
                // to reduce the size of the transition table and create bitmasks.
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                10, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 11, 6, 6, 6, 5, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
            };

        private static final byte[] TRANS_TABLE =
            {
                // The second part is a transition table that maps a combination
                // of a state of the automaton and a character class to a state.
                0, 12, 24, 36, 60, 96, 84, 12, 12, 12, 48, 72, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                12, 0, 12, 12, 12, 12, 12, 0, 12, 0, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 24, 12, 12,
                12, 12, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 12, 12, 24, 12, 12,
                12, 12, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12, 12, 36, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12,
                12, 36, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12
            };

        private int _codep;

        final StringBuilder _buffer;

        public Utf8StringBuilder() {
            _appendable = new StringBuilder();
            _buffer = (StringBuilder)_appendable;
        }

        public int length() {
            return _buffer.length();
        }

        public void reset() {
            _state = UTF8_ACCEPT;
            _buffer.setLength(0);
        }

        @Override
        public String toString() {
            checkState();
            return _buffer.toString();
        }

        private void checkCharAppend() throws IOException {
            if (_state != UTF8_ACCEPT) {
                _appendable.append(REPLACEMENT);
                int state = _state;
                _state = UTF8_ACCEPT;
                throw new Utf8StringBuilder.NotUtf8Exception("char appended in state " + state);
            }
        }

        public void append(char c) {
            try {
                checkCharAppend();
                _appendable.append(c);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        public void append(byte b) {
            try {
                appendByte(b);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        protected void appendByte(byte b) throws IOException {

            if (b > 0 && _state == UTF8_ACCEPT) {
                _appendable.append((char)(b & 0xFF));
            } else {
                int i = b & 0xFF;
                int type = BYTE_TABLE[i];
                _codep = _state == UTF8_ACCEPT ? (0xFF >> type) & i : (i & 0x3F) | (_codep << 6);
                int next = TRANS_TABLE[_state + type];

                switch (next) {
                    case UTF8_ACCEPT:
                        _state = next;
                        if (_codep < Character.MIN_HIGH_SURROGATE) {
                            _appendable.append((char)_codep);
                        } else {
                            for (char c : Character.toChars(_codep)) {
                                _appendable.append(c);
                            }
                        }
                        break;

                    case UTF8_REJECT:
                        String reason = "byte " + toHexString(new byte[] {b}, 0, 1) + " in state " + (_state / 12);
                        _codep = 0;
                        _state = UTF8_ACCEPT;
                        _appendable.append(REPLACEMENT);
                        throw new Utf8StringBuilder.NotUtf8Exception(reason);

                    default:
                        _state = next;
                }
            }
        }

        public boolean isUtf8SequenceComplete() {
            return _state == UTF8_ACCEPT;
        }

        @SuppressWarnings("serial")
        public static class NotUtf8Exception extends IllegalArgumentException {
            public NotUtf8Exception(String reason) {
                super("Not valid UTF8! " + reason);
            }
        }

        protected void checkState() {
            if (!isUtf8SequenceComplete()) {
                _codep = 0;
                _state = UTF8_ACCEPT;
                try {
                    _appendable.append(REPLACEMENT);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                throw new Utf8StringBuilder.NotUtf8Exception("incomplete UTF8 sequence");
            }
        }

        public String toReplacedString() {
            if (!isUtf8SequenceComplete()) {
                _codep = 0;
                _state = UTF8_ACCEPT;
                try {
                    _appendable.append(REPLACEMENT);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return _appendable.toString();
        }

        public static String toHexString(byte[] b, int offset, int length) {
            StringBuilder buf = new StringBuilder();
            for (int i = offset; i < offset + length; i++) {
                int bi = 0xff & b[i];
                int c = '0' + (bi / 16) % 16;
                if (c > '9') {
                    c = 'A' + (c - '0' - 10);
                }
                buf.append((char)c);
                c = '0' + bi % 16;
                if (c > '9') {
                    c = 'a' + (c - '0' - 10);
                }
                buf.append((char)c);
            }
            return buf.toString();
        }
    }
}