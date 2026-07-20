#include "lumina_sqli.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifdef LUMINA_SQLI_INSTRUMENT
#include "lumina_sqli_internal.h"
#endif

enum {
    TOKEN_CAPACITY = 24,
    SIGNATURE_CAPACITY = 8
};

typedef enum OperatorKind {
    OPERATOR_GENERIC = 0,
    OPERATOR_COMPARE = 1,
    OPERATOR_UNARY = 2,
    OPERATOR_HASH = 3,
    OPERATOR_BITWISE = 4,
    OPERATOR_OTHER = 5
} OperatorKind;

typedef struct Token {
    char type;
    uint8_t operator_kind;
} Token;

typedef enum QuoteContext {
    QUOTE_CONTEXT_NONE = 0,
    QUOTE_CONTEXT_SINGLE = 1,
    QUOTE_CONTEXT_DOUBLE = 2
} QuoteContext;

typedef struct ScanOptions {
    QuoteContext quote_context;
    uint8_t hash_is_comment;
} ScanOptions;

typedef struct AttackShape {
    char bytes[6];
    uint8_t length;
} AttackShape;

#define ATTACK_SHAPE(value) {value, (uint8_t)(sizeof(value) - 1U)}

/* Grouped by first token so the hot matcher scans one compact range. */
static const AttackShape attack_grammar_shapes[] = {
    ATTACK_SHAPE("1&1"), ATTACK_SHAPE("1&1c"), ATTACK_SHAPE("1&f(1"),
    ATTACK_SHAPE("1&f(E"), ATTACK_SHAPE("1&f(s"), ATTACK_SHAPE("1&f(v"),
    ATTACK_SHAPE("1&sos"), ATTACK_SHAPE("1&v"), ATTACK_SHAPE("1&vc"),
    ATTACK_SHAPE("1);Tk"), ATTACK_SHAPE("1;E1c"), ATTACK_SHAPE("1;E1o"),
    ATTACK_SHAPE("1;EnE"), ATTACK_SHAPE("1;Enk"), ATTACK_SHAPE("1;Esc"),
    ATTACK_SHAPE("1;Eso"), ATTACK_SHAPE("1;Tkn"), ATTACK_SHAPE("1;Tnn"),
    ATTACK_SHAPE("1;Tns"), ATTACK_SHAPE("1Eokn"), ATTACK_SHAPE("1Esc"),
    ATTACK_SHAPE("1Eson"), ATTACK_SHAPE("1Tnnc"), ATTACK_SHAPE("1Tnsc"),
    ATTACK_SHAPE("1Tnso"), ATTACK_SHAPE("1UE"), ATTACK_SHAPE("1UE1"),
    ATTACK_SHAPE("1UE1c"), ATTACK_SHAPE("1UE1k"), ATTACK_SHAPE("1UE1n"),
    ATTACK_SHAPE("1UE1o"), ATTACK_SHAPE("1UEf("), ATTACK_SHAPE("1UEnk"),
    ATTACK_SHAPE("1UEvk"), ATTACK_SHAPE("1Uon"), ATTACK_SHAPE("1c"),
    ATTACK_SHAPE("1f(1)"),
    ATTACK_SHAPE("Enknc"), ATTACK_SHAPE("Eoknk"),
    ATTACK_SHAPE("UE1c"), ATTACK_SHAPE("UE1k("), ATTACK_SHAPE("UE1kn"),
    ATTACK_SHAPE("UE1o"), ATTACK_SHAPE("UEnk("), ATTACK_SHAPE("UEnkn"),
    ATTACK_SHAPE("UEvk("), ATTACK_SHAPE("UEvkn"),
    ATTACK_SHAPE("X"),
    ATTACK_SHAPE("f((1)"), ATTACK_SHAPE("f((E1"), ATTACK_SHAPE("f((s)"),
    ATTACK_SHAPE("f((v)"), ATTACK_SHAPE("f(1)"), ATTACK_SHAPE("f(1)c"),
    ATTACK_SHAPE("f(1)n"), ATTACK_SHAPE("f(1)o"), ATTACK_SHAPE("f(E1)"),
    ATTACK_SHAPE("f(s)"), ATTACK_SHAPE("f(s)c"), ATTACK_SHAPE("f(s)n"),
    ATTACK_SHAPE("f(s)o"), ATTACK_SHAPE("f(v)"), ATTACK_SHAPE("f(v)c"),
    ATTACK_SHAPE("f(v)n"), ATTACK_SHAPE("f(v)o"),
    ATTACK_SHAPE("n&1"), ATTACK_SHAPE("n&1c"), ATTACK_SHAPE("n&sos"),
    ATTACK_SHAPE("n&v"), ATTACK_SHAPE("n&vc"), ATTACK_SHAPE("n);Tk"),
    ATTACK_SHAPE("n1Uon"), ATTACK_SHAPE("n;E1c"), ATTACK_SHAPE("n;E1o"),
    ATTACK_SHAPE("n;EnE"), ATTACK_SHAPE("n;Tnn"), ATTACK_SHAPE("nEokn"),
    ATTACK_SHAPE("nEsc"), ATTACK_SHAPE("nksc"), ATTACK_SHAPE("nkson"),
    ATTACK_SHAPE("no(n,"), ATTACK_SHAPE("no(no"), ATTACK_SHAPE("nof(1"),
    ATTACK_SHAPE("nos1n"), ATTACK_SHAPE("nsnsc"),
    ATTACK_SHAPE("s&(Ef"), ATTACK_SHAPE("s&1"), ATTACK_SHAPE("s&1c"),
    ATTACK_SHAPE("s&f(1"), ATTACK_SHAPE("s&sos"), ATTACK_SHAPE("s&v"),
    ATTACK_SHAPE("s&vc"), ATTACK_SHAPE("s)&(E"), ATTACK_SHAPE("s)&1"),
    ATTACK_SHAPE("s)&1c"), ATTACK_SHAPE("s)&1o"), ATTACK_SHAPE("s)&f("),
    ATTACK_SHAPE("s)&so"), ATTACK_SHAPE("s)&so"), ATTACK_SHAPE("s)&v"),
    ATTACK_SHAPE("s)&v"), ATTACK_SHAPE("s)&vc"), ATTACK_SHAPE("s)&vo"),
    ATTACK_SHAPE("s)&vo"), ATTACK_SHAPE("s)Esc"), ATTACK_SHAPE("s)Eso"),
    ATTACK_SHAPE("s)UE1"), ATTACK_SHAPE("s)UEf"), ATTACK_SHAPE("s)UEn"),
    ATTACK_SHAPE("s)UEv"), ATTACK_SHAPE("s1nc"), ATTACK_SHAPE("s;Tnn"),
    ATTACK_SHAPE("sEnEn"), ATTACK_SHAPE("sEsc"), ATTACK_SHAPE("sTnnc"),
    ATTACK_SHAPE("sTnsc"), ATTACK_SHAPE("sTnso"), ATTACK_SHAPE("sUE1"),
    ATTACK_SHAPE("sUE1c"), ATTACK_SHAPE("sUE1k"), ATTACK_SHAPE("sUE1o"),
    ATTACK_SHAPE("sUEf("), ATTACK_SHAPE("sUEnk"), ATTACK_SHAPE("sUEvk"),
    ATTACK_SHAPE("sc"), ATTACK_SHAPE("sf(1n"), ATTACK_SHAPE("so1n("),
    ATTACK_SHAPE("sof(1"), ATTACK_SHAPE("sof(E"), ATTACK_SHAPE("sof(s"),
    ATTACK_SHAPE("sof(v"), ATTACK_SHAPE("son(1"), ATTACK_SHAPE("son(E"),
    ATTACK_SHAPE("son(s"), ATTACK_SHAPE("son(v"), ATTACK_SHAPE("son;n"),
    ATTACK_SHAPE("sonoo"), ATTACK_SHAPE("sos")
};

#undef ATTACK_SHAPE

enum {
    SHAPE_1_BEGIN = 0,
    SHAPE_E_BEGIN = 37,
    SHAPE_U_BEGIN = 39,
    SHAPE_X_BEGIN = 47,
    SHAPE_F_BEGIN = 48,
    SHAPE_N_BEGIN = 65,
    SHAPE_S_BEGIN = 85,
    ATTACK_SHAPE_COUNT = 138
};

_Static_assert(sizeof(AttackShape) == 7U, "attack shape must remain compact");
_Static_assert(sizeof(attack_grammar_shapes) /
                   sizeof(attack_grammar_shapes[0]) == ATTACK_SHAPE_COUNT,
               "shape ranges must cover the complete grammar table");

static void add_work(size_t *work, size_t amount)
{
    if (work != NULL) {
        if (*work > SIZE_MAX - amount) {
            *work = SIZE_MAX;
        } else {
            *work += amount;
        }
    }
}

static uint8_t ascii_lower(uint8_t value)
{
    if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
        return (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
    }
    return value;
}

static int is_space_byte(uint8_t value)
{
    return value <= (uint8_t)' ';
}

static int is_digit_byte(uint8_t value)
{
    return value >= (uint8_t)'0' && value <= (uint8_t)'9';
}

static int is_hex_byte(uint8_t value)
{
    const uint8_t lower = ascii_lower(value);
    return is_digit_byte(value) ||
           (lower >= (uint8_t)'a' && lower <= (uint8_t)'f');
}

static int is_word_start(uint8_t value)
{
    const uint8_t lower = ascii_lower(value);
    return (lower >= (uint8_t)'a' && lower <= (uint8_t)'z') ||
           value == (uint8_t)'_' || value >= UINT8_C(0x80);
}

static int is_word_continue(uint8_t value)
{
    return is_word_start(value) || is_digit_byte(value) ||
           value == (uint8_t)'$';
}

static int word_is(const uint8_t *data, size_t start, size_t length,
                   const char *word, size_t word_length, size_t *work)
{
    size_t index;

    if (length != word_length) {
        return 0;
    }
    for (index = 0U; index < length; ++index) {
        add_work(work, 1U);
        if (ascii_lower(data[start + index]) != (uint8_t)word[index]) {
            return 0;
        }
    }
    return 1;
}

static Token classify_word(const uint8_t *data, size_t start, size_t length,
                           size_t *work)
{
    Token token = {'n', OPERATOR_GENERIC};

    if (word_is(data, start, length, "and", 3U, work) ||
        word_is(data, start, length, "or", 2U, work) ||
        word_is(data, start, length, "xor", 3U, work)) {
        token.type = '&';
    } else if (word_is(data, start, length, "union", 5U, work)) {
        token.type = 'U';
    } else if (word_is(data, start, length, "select", 6U, work) ||
               word_is(data, start, length, "update", 6U, work) ||
               word_is(data, start, length, "waitfor", 7U, work) ||
               word_is(data, start, length, "set", 3U, work)) {
        token.type = 'E';
    } else if (word_is(data, start, length, "drop", 4U, work) ||
               word_is(data, start, length, "delete", 6U, work) ||
               word_is(data, start, length, "exec", 4U, work) ||
               word_is(data, start, length, "execute", 7U, work) ||
               word_is(data, start, length, "insert", 6U, work)) {
        token.type = 'T';
    } else if (word_is(data, start, length, "from", 4U, work) ||
               word_is(data, start, length, "where", 5U, work) ||
               word_is(data, start, length, "into", 4U, work)) {
        token.type = 'k';
    } else if (word_is(data, start, length, "null", 4U, work)) {
        token.type = 'v';
    } else if (word_is(data, start, length, "is", 2U, work) ||
               word_is(data, start, length, "like", 4U, work)) {
        token.type = 'o';
        token.operator_kind = OPERATOR_COMPARE;
    } else if (word_is(data, start, length, "all", 3U, work) ||
               word_is(data, start, length, "delay", 5U, work) ||
               word_is(data, start, length, "distinct", 8U, work)) {
        token.type = '\0';
    } else if (word_is(data, start, length, "sleep", 5U, work) ||
               word_is(data, start, length, "pg_sleep", 8U, work) ||
               word_is(data, start, length, "benchmark", 9U, work) ||
               word_is(data, start, length, "char", 4U, work) ||
               word_is(data, start, length, "concat", 6U, work) ||
               word_is(data, start, length, "coalesce", 8U, work) ||
               word_is(data, start, length, "extractvalue", 12U, work) ||
               word_is(data, start, length, "updatexml", 9U, work) ||
               word_is(data, start, length, "load_file", 9U, work) ||
               word_is(data, start, length, "count", 5U, work)) {
        token.type = 'f';
    }
    return token;
}

static void append_token(Token *tokens, size_t *count, Token token)
{
    if (token.type != '\0' && *count < TOKEN_CAPACITY) {
        tokens[*count] = token;
        ++(*count);
    }
}

static size_t scan_string(const uint8_t *data, size_t len, size_t start,
                          uint8_t quote, int honor_backslash, size_t *work)
{
    size_t index = start;

    while (index < len) {
        const uint8_t value = data[index];
        add_work(work, 1U);
        ++index;
        if (value == quote) {
            if (index < len && data[index] == quote) {
                add_work(work, 1U);
                ++index;
                continue;
            }
            break;
        }
        if (honor_backslash != 0 && value == (uint8_t)'\\' && index < len) {
            add_work(work, 1U);
            ++index;
        }
    }
    return index;
}

static size_t scan_number(const uint8_t *data, size_t len, size_t start,
                          size_t *work)
{
    size_t index = start;

    if (index < len && (data[index] == (uint8_t)'+' ||
                        data[index] == (uint8_t)'-')) {
        add_work(work, 1U);
        ++index;
    }
    if (len - index >= 2U && data[index] == (uint8_t)'0' &&
        ascii_lower(data[index + 1U]) == (uint8_t)'x') {
        add_work(work, 2U);
        index += 2U;
        while (index < len && is_hex_byte(data[index])) {
            add_work(work, 1U);
            ++index;
        }
        return index;
    }
    while (index < len && is_digit_byte(data[index])) {
        add_work(work, 1U);
        ++index;
    }
    if (index < len && data[index] == (uint8_t)'.') {
        add_work(work, 1U);
        ++index;
        while (index < len && is_digit_byte(data[index])) {
            add_work(work, 1U);
            ++index;
        }
    }
    if (index < len && ascii_lower(data[index]) == (uint8_t)'e') {
        size_t exponent = index + 1U;
        add_work(work, 1U);
        if (exponent < len && (data[exponent] == (uint8_t)'+' ||
                               data[exponent] == (uint8_t)'-')) {
            add_work(work, 1U);
            ++exponent;
        }
        if (exponent < len && is_digit_byte(data[exponent])) {
            index = exponent + 1U;
            add_work(work, 1U);
            while (index < len && is_digit_byte(data[index])) {
                add_work(work, 1U);
                ++index;
            }
        }
    }
    return index;
}

static size_t tokenize(const uint8_t *data, size_t len, ScanOptions options,
                       Token *tokens, size_t *work)
{
    size_t count = 0U;
    size_t index = 0U;
    int pending_comment = 0;
    int seen_hash_operator = 0;

    if (options.quote_context != QUOTE_CONTEXT_NONE) {
        const uint8_t quote = options.quote_context == QUOTE_CONTEXT_SINGLE
                                  ? (uint8_t)'\''
                                  : (uint8_t)'"';
        Token string_token = {'s', OPERATOR_GENERIC};
        index = scan_string(data, len, 0U, quote, 0, work);
        append_token(tokens, &count, string_token);
    }

    while (index < len) {
        const uint8_t value = data[index];
        Token token = {'o', OPERATOR_GENERIC};
        add_work(work, 1U);

        if (is_space_byte(value)) {
            ++index;
            continue;
        }

        if (len - index >= 3U && value == (uint8_t)'/' &&
            data[index + 1U] == (uint8_t)'*' &&
            data[index + 2U] == (uint8_t)'!') {
            Token evil = {'X', OPERATOR_GENERIC};
            append_token(tokens, &count, evil);
            return count;
        }

        if (len - index >= 2U && value == (uint8_t)'/' &&
            data[index + 1U] == (uint8_t)'*') {
            index += 2U;
            add_work(work, 1U);
            while (len - index >= 2U &&
                   !(data[index] == (uint8_t)'*' &&
                     data[index + 1U] == (uint8_t)'/')) {
                add_work(work, 1U);
                ++index;
            }
            if (len - index >= 2U) {
                add_work(work, 2U);
                index += 2U;
            }
            pending_comment = 1;
            continue;
        }

        if (len - index >= 2U && value == (uint8_t)'-' &&
            data[index + 1U] == (uint8_t)'-' &&
            (count == 0U || tokens[count - 1U].type == 'n')) {
            if (count != 0U) {
                Token path_operator = {'o', OPERATOR_UNARY};
                append_token(tokens, &count, path_operator);
            }
            add_work(work, 2U);
            index += 2U;
            continue;
        }

        if (len - index >= 2U && value == (uint8_t)'-' &&
            data[index + 1U] == (uint8_t)'-' &&
            count != 0U) {
            index += 2U;
            add_work(work, 1U);
            while (index < len && data[index] != (uint8_t)'\n' &&
                   data[index] != (uint8_t)'\r') {
                add_work(work, 1U);
                ++index;
            }
            pending_comment = 1;
            continue;
        }

        if (value == (uint8_t)'#' && options.hash_is_comment != 0U &&
            count >= 3U && seen_hash_operator == 0) {
            ++index;
            while (index < len && data[index] != (uint8_t)'\n' &&
                   data[index] != (uint8_t)'\r') {
                add_work(work, 1U);
                ++index;
            }
            pending_comment = 1;
            continue;
        }

        pending_comment = 0;

        if (value == (uint8_t)'\'' || value == (uint8_t)'"') {
            token.type = 's';
            index = scan_string(data, len, index + 1U, value, 1, work);
            append_token(tokens, &count, token);
            continue;
        }

        if (value == (uint8_t)'`') {
            token.type = 'n';
            index = scan_string(data, len, index + 1U, value, 0, work);
            append_token(tokens, &count, token);
            continue;
        }

        if (value == (uint8_t)'[') {
            token.type = 'n';
            ++index;
            while (index < len && data[index] != (uint8_t)']') {
                add_work(work, 1U);
                ++index;
            }
            if (index < len) {
                add_work(work, 1U);
                ++index;
            }
            append_token(tokens, &count, token);
            continue;
        }

        if (is_digit_byte(value) ||
            ((value == (uint8_t)'+' || value == (uint8_t)'-') &&
             len - index >= 2U && is_digit_byte(data[index + 1U]) &&
             (count == 0U ||
              (tokens[count - 1U].type != 'n' &&
               tokens[count - 1U].type != '1' &&
               tokens[count - 1U].type != 's' &&
               tokens[count - 1U].type != 'v' &&
               tokens[count - 1U].type != ')')))) {
            token.type = '1';
            index = scan_number(data, len, index, work);
            append_token(tokens, &count, token);
            continue;
        }

        if (value == (uint8_t)'@') {
            token.type = 'v';
            ++index;
            if (index < len && data[index] == (uint8_t)'@') {
                add_work(work, 1U);
                ++index;
            }
            while (index < len && is_word_continue(data[index])) {
                add_work(work, 1U);
                ++index;
            }
            append_token(tokens, &count, token);
            continue;
        }

        if (is_word_start(value)) {
            const size_t start = index;
            ++index;
            while (index < len && is_word_continue(data[index])) {
                add_work(work, 1U);
                ++index;
            }
            token = classify_word(data, start, index - start, work);
            if (token.type == 'E' && index < len &&
                data[index] == (uint8_t)'(' &&
                word_is(data, start, index - start, "waitfor", 7U, work)) {
                token.type = 'n';
            }
            append_token(tokens, &count, token);
            continue;
        }

        ++index;
        if (value == (uint8_t)'(' || value == (uint8_t)')' ||
            value == (uint8_t)';' || value == (uint8_t)',') {
            token.type = (char)value;
        } else if (value == (uint8_t)'&' || value == (uint8_t)'|') {
            if (index < len && data[index] == value) {
                token.type = '&';
                add_work(work, 1U);
                ++index;
            } else {
                token.type = 'o';
                token.operator_kind = OPERATOR_BITWISE;
            }
        } else {
            token.type = 'o';
            if (value == (uint8_t)'=' || value == (uint8_t)'<' ||
                value == (uint8_t)'>' || value == (uint8_t)'!') {
                token.operator_kind = OPERATOR_COMPARE;
                if (index < len &&
                    (data[index] == (uint8_t)'=' ||
                     data[index] == (uint8_t)'>')) {
                    add_work(work, 1U);
                    ++index;
                }
            } else if (value == (uint8_t)'#') {
                token.operator_kind = OPERATOR_HASH;
                seen_hash_operator = 1;
            } else if (value == (uint8_t)'^') {
                token.operator_kind = OPERATOR_BITWISE;
            } else if (value == (uint8_t)'+' || value == (uint8_t)'-' ||
                       value == (uint8_t)'~') {
                token.operator_kind = OPERATOR_UNARY;
            } else if (value != (uint8_t)'*' && value != (uint8_t)'/' &&
                       value != (uint8_t)'%') {
                token.operator_kind = OPERATOR_OTHER;
            }
        }
        append_token(tokens, &count, token);
    }

    if (pending_comment != 0) {
        Token comment = {'c', OPERATOR_GENERIC};
        append_token(tokens, &count, comment);
    }
    return count;
}

static int is_foldable_scalar(char type)
{
    return type == '1' || type == 'v';
}

static size_t normalize_tokens(const Token *raw, size_t raw_count,
                               Token *normalized)
{
    size_t source = 0U;
    size_t target = 0U;
    int union_projection = 0;
    int function_arguments = 0;

    while (source < raw_count && target < TOKEN_CAPACITY) {
        if (raw[source].type == ')' && target != 0U &&
            normalized[target - 1U].type == ')') {
            ++source;
            continue;
        }

        if (raw[source].type == 'o' && target == 0U &&
            (raw[source].operator_kind == OPERATOR_UNARY ||
             (source + 1U < raw_count && raw[source + 1U].type == 'n'))) {
            ++source;
            continue;
        }

        if (raw[source].type == 'o' &&
            raw[source].operator_kind == OPERATOR_OTHER && target != 0U &&
            normalized[target - 1U].type == '(') {
            ++source;
            continue;
        }

        if (raw[source].type == 'n' && target != 0U &&
            normalized[target - 1U].type == 'n' &&
            !(target >= 2U && normalized[target - 2U].type == 'T')) {
            ++source;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_COMPARE &&
            (raw[source + 2U].type == '1' ||
             raw[source + 2U].type == 'n' ||
             raw[source + 2U].type == 's' ||
             raw[source + 2U].type == 'v')) {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_COMPARE &&
            raw[source + 2U].type == 'E') {
            Token keyword = {'k', OPERATOR_GENERIC};
            normalized[target] = raw[source];
            ++target;
            if (target < TOKEN_CAPACITY) {
                normalized[target] = keyword;
                ++target;
            }
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_UNARY &&
            (raw[source + 2U].type == '1' ||
             raw[source + 2U].type == 'n')) {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_UNARY &&
            raw[source + 2U].type == 'E') {
            Token keyword = {'k', OPERATOR_GENERIC};
            normalized[target] = raw[source];
            ++target;
            if (target < TOKEN_CAPACITY) {
                normalized[target] = keyword;
                ++target;
            }
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == '1' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_HASH &&
            raw[source + 2U].type == '1') {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_HASH &&
            raw[source + 2U].type == '1') {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            raw[source].type == 'n' && raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind != OPERATOR_HASH &&
            raw[source + 2U].type == 'n') {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (source + 2U < raw_count &&
            is_foldable_scalar(raw[source].type) &&
            raw[source + 1U].type == 'o' &&
            raw[source + 1U].operator_kind == OPERATOR_COMPARE &&
            raw[source + 2U].type == raw[source].type) {
            normalized[target] = raw[source];
            ++target;
            source += 3U;
            continue;
        }

        if (raw[source].type == 'U') {
            union_projection = 1;
        }
        if (raw[source].type == 'f' && source + 1U < raw_count &&
            raw[source + 1U].type == '(') {
            function_arguments = 1;
        }
        if (union_projection != 0 && raw[source].type == ',' &&
            source + 1U < raw_count) {
            source += 2U;
            continue;
        }
        if (function_arguments != 0 && raw[source].type == ',' &&
            source + 1U < raw_count) {
            source += 2U;
            continue;
        }
        if (union_projection != 0 && raw[source].type == 'k') {
            union_projection = 0;
        }
        if (function_arguments != 0 && raw[source].type == ')') {
            function_arguments = 0;
        }

        normalized[target] = raw[source];
        ++target;
        ++source;
    }

    if (target >= 4U && normalized[0].type == 's' &&
        normalized[1].type == '1' && normalized[target - 1U].type == 'c') {
        size_t index;
        int has_name = 0;
        int has_compare = 0;
        int allowed = 1;

        for (index = 2U; index + 1U < target; ++index) {
            const char type = normalized[index].type;
            if (type == 'n') {
                has_name = 1;
            } else if (type == 'o' &&
                       normalized[index].operator_kind == OPERATOR_COMPARE) {
                has_compare = 1;
            } else if (type != 'o' && type != '1' && type != ',') {
                allowed = 0;
            }
        }
        if (allowed != 0 && has_name != 0 && has_compare != 0) {
            normalized[2].type = 'n';
            normalized[2].operator_kind = OPERATOR_GENERIC;
            normalized[3] = normalized[target - 1U];
            target = 4U;
        }
    }

    if (target >= 5U && normalized[0].type == 's' &&
        normalized[1].type == 'o') {
        size_t number_index = 2U;
        size_t name_index;
        size_t paren_index;
        size_t prefix_index;
        int has_prefix_name = 0;
        int has_prefix_compare = 0;

        while (number_index < target && normalized[number_index].type != '1') {
            ++number_index;
        }
        for (prefix_index = 2U; prefix_index < number_index; ++prefix_index) {
            if (normalized[prefix_index].type == 'n') {
                has_prefix_name = 1;
            }
            if (normalized[prefix_index].type == 'o' &&
                normalized[prefix_index].operator_kind == OPERATOR_COMPARE) {
                has_prefix_compare = 1;
            }
        }
        name_index = number_index < target ? number_index + 1U : target;
        while (name_index < target && normalized[name_index].type != 'n') {
            ++name_index;
        }
        paren_index = name_index < target ? name_index + 1U : target;
        while (paren_index < target && normalized[paren_index].type != '(') {
            ++paren_index;
        }
        if (number_index < target && name_index < target &&
            paren_index < target && has_prefix_name != 0 &&
            has_prefix_compare != 0) {
            normalized[2] = normalized[number_index];
            normalized[3] = normalized[name_index];
            normalized[4] = normalized[paren_index];
            target = 5U;
        }
    }
    return target;
}

static int shape_range(char first, size_t *begin, size_t *end)
{
    switch (first) {
    case '1':
        *begin = SHAPE_1_BEGIN;
        *end = SHAPE_E_BEGIN;
        return 1;
    case 'E':
        *begin = SHAPE_E_BEGIN;
        *end = SHAPE_U_BEGIN;
        return 1;
    case 'U':
        *begin = SHAPE_U_BEGIN;
        *end = SHAPE_X_BEGIN;
        return 1;
    case 'X':
        *begin = SHAPE_X_BEGIN;
        *end = SHAPE_F_BEGIN;
        return 1;
    case 'f':
        *begin = SHAPE_F_BEGIN;
        *end = SHAPE_N_BEGIN;
        return 1;
    case 'n':
        *begin = SHAPE_N_BEGIN;
        *end = SHAPE_S_BEGIN;
        return 1;
    case 's':
        *begin = SHAPE_S_BEGIN;
        *end = ATTACK_SHAPE_COUNT;
        return 1;
    default:
        *begin = 0U;
        *end = 0U;
        return 0;
    }
}

static int matches_attack_shape(const uint8_t *data, size_t data_len,
                                const Token *tokens, size_t count,
                                size_t *work)
{
    const size_t prefix_length = count < 5U ? count : 5U;
    size_t begin;
    size_t end;
    size_t shape_index;

    if (count == 0U || shape_range(tokens[0].type, &begin, &end) == 0) {
        return 0;
    }
    for (shape_index = begin; shape_index < end; ++shape_index) {
        const AttackShape *entry = &attack_grammar_shapes[shape_index];
        const char *shape = entry->bytes;
        const size_t length = entry->length;
        size_t token_index;
        int equal = 1;

        add_work(work, 1U);
        if (length > count || length > SIGNATURE_CAPACITY) {
            continue;
        }
        if (length >= 2U) {
            add_work(work, 1U);
            if (shape[1] != tokens[1].type) {
                continue;
            }
        }
        if (length == 5U && shape[0] == 'n' && shape[1] == 'o' &&
            shape[2] == '(' && shape[3] == 'n' &&
            shape[4] == 'o' &&
            tokens[1].operator_kind != OPERATOR_BITWISE) {
            continue;
        }
        if (length == 5U && shape[0] == 's' && shape[1] == 'o' &&
            shape[2] == 'n' && shape[3] == ';' &&
            shape[4] == 'n' &&
            tokens[1].operator_kind == OPERATOR_OTHER) {
            continue;
        }
        if (length == 3U && shape[0] == 's' && shape[1] == 'o' &&
            shape[2] == 's' &&
            tokens[1].operator_kind != OPERATOR_GENERIC) {
            continue;
        }
        if (length == 5U && shape[0] == 's' && shape[1] == 'o' &&
            shape[2] == 'n' && shape[3] == 'o' && shape[4] == 'o' &&
            (tokens[1].operator_kind != OPERATOR_BITWISE || data_len < 2U ||
             data[0] != (uint8_t)'"' ||
             data[data_len - 1U] != (uint8_t)'"')) {
            continue;
        }
        if (length == 5U && shape[0] == 'n' && shape[1] == 'o' &&
            shape[2] == 'f' && shape[3] == '(' &&
            shape[4] == '1' &&
            tokens[1].operator_kind != OPERATOR_COMPARE &&
            tokens[1].operator_kind != OPERATOR_UNARY) {
            continue;
        }
        if (length == 5U && shape[0] == 's' && shape[1] == 'o' &&
            shape[2] == '1' && shape[3] == 'n' &&
            shape[4] == '(' &&
            tokens[1].operator_kind != OPERATOR_UNARY) {
            continue;
        }
        if (length != prefix_length &&
            !(length >= 4U && shape[length - 1U] == '(' &&
              (shape[0] == 'U' ||
               (length >= 2U && shape[1] == 'U') ||
               (length >= 3U && shape[2] == 'U'))) &&
            !(length >= 3U && shape[length - 2U] == '&' &&
              (shape[length - 1U] == '1' ||
               shape[length - 1U] == 'v') &&
              count >= length + 2U && tokens[length].type == 'o' &&
              tokens[length + 1U].type == 'n')) {
            continue;
        }
        for (token_index = length >= 2U ? 2U : 1U;
             token_index < length; ++token_index) {
            add_work(work, 1U);
            if (tokens[token_index].type != shape[token_index]) {
                equal = 0;
                break;
            }
        }
        if (equal != 0) {
            return 1;
        }
    }
    return 0;
}

static int summarize_input(const uint8_t *data, size_t len, int *has_hash,
                           int *has_single_quote, int *has_double_quote,
                           size_t *work)
{
    size_t index;

    *has_hash = 0;
    *has_single_quote = 0;
    *has_double_quote = 0;
    for (index = 0U; index < len; ++index) {
        const uint8_t value = data[index];
        add_work(work, 1U);
        if (value == (uint8_t)'/' && len - index >= 3U &&
            data[index + 1U] == (uint8_t)'*' &&
            data[index + 2U] == (uint8_t)'!') {
            add_work(work, 2U);
            return 1;
        }
        if (value == (uint8_t)'#') {
            *has_hash = 1;
        } else if (value == (uint8_t)'\'') {
            *has_single_quote = 1;
        } else if (value == (uint8_t)'"') {
            *has_double_quote = 1;
        }
    }
    return 0;
}

static int detect_core(const uint8_t *data, size_t len, size_t *work)
{
    size_t leading_index = 0U;
    int has_hash = 0;
    int leading_hash = 0;
    int has_single_quote = 0;
    int has_double_quote = 0;
    unsigned int context_value;
    unsigned int hash_value;

    if (work != NULL) {
        *work = 0U;
    }
    if (data == NULL && len != 0U) {
        return 0;
    }

    if (summarize_input(data, len, &has_hash, &has_single_quote,
                        &has_double_quote, work) != 0) {
        return 1;
    }

    while (leading_index < len && is_space_byte(data[leading_index])) {
        add_work(work, 1U);
        ++leading_index;
    }
    if (leading_index < len && data[leading_index] == (uint8_t)'#') {
        add_work(work, 1U);
        leading_hash = 1;
    }

    for (context_value = (unsigned int)QUOTE_CONTEXT_NONE;
         context_value <= (unsigned int)QUOTE_CONTEXT_DOUBLE;
         ++context_value) {
        if ((context_value == (unsigned int)QUOTE_CONTEXT_SINGLE &&
             has_single_quote == 0) ||
            (context_value == (unsigned int)QUOTE_CONTEXT_DOUBLE &&
             has_double_quote == 0)) {
            continue;
        }

        for (hash_value = 0U; hash_value <= (has_hash != 0 ? 1U : 0U);
             ++hash_value) {
            Token raw[TOKEN_CAPACITY];
            Token normalized[TOKEN_CAPACITY];
            ScanOptions options;
            size_t raw_count;
            size_t normalized_count;
            if (context_value == (unsigned int)QUOTE_CONTEXT_NONE &&
                leading_hash != 0) {
                continue;
            }

            options.quote_context = (QuoteContext)context_value;
            options.hash_is_comment = (uint8_t)hash_value;
            raw_count = tokenize(data, len, options, raw, work);
            normalized_count = normalize_tokens(raw, raw_count, normalized);
            if (matches_attack_shape(data, len, normalized, normalized_count,
                                     work) != 0) {
                return 1;
            }
        }
    }
    return 0;
}

int lumina_sqli_detect(const uint8_t *data, size_t len)
{
    return detect_core(data, len, NULL);
}

#ifdef LUMINA_SQLI_INSTRUMENT
int lumina_sqli_detect_instrumented(const uint8_t *data, size_t len,
                                    size_t *work)
{
    return detect_core(data, len, work);
}
#endif
