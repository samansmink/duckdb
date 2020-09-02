#pragma once
#include <bitset>

#define TEST_KEY (const unsigned char*) "0123456789012345678901234567890"
#define TEST_NONCE (const unsigned char*)"0123456789012345678901234567890"
#define VECTOR_SIZE 1024
#define NONCE_BYTES 16

typedef uint8_t data_t;
typedef data_t *data_ptr_t;
typedef std::bitset<1024> nullmask_t;
typedef uint64_t idx_t;
typedef uint16_t sel_t;

struct sum_state_t {
    double value;
    bool isset;
};

struct secure_sum_state_t {
    sum_state_t* secure_state;
};

enum class ExpressionType : uint8_t {
    INVALID = 0,

    // explicitly cast left as right (right is integer in ValueType enum)
    OPERATOR_CAST = 12,
    // logical not operator
    OPERATOR_NOT = 13,
    // is null operator
    OPERATOR_IS_NULL = 14,
    // is not null operator
    OPERATOR_IS_NOT_NULL = 15,

    // -----------------------------
    // Comparison Operators
    // -----------------------------
    // equal operator between left and right
    COMPARE_EQUAL = 25,
    // compare initial boundary
    COMPARE_BOUNDARY_START = COMPARE_EQUAL,
    // inequal operator between left and right
    COMPARE_NOTEQUAL = 26,
    // less than operator between left and right
    COMPARE_LESSTHAN = 27,
    // greater than operator between left and right
    COMPARE_GREATERTHAN = 28,
    // less than equal operator between left and right
    COMPARE_LESSTHANOREQUALTO = 29,
    // greater than equal operator between left and right
    COMPARE_GREATERTHANOREQUALTO = 30,
    // IN operator [left IN (right1, right2, ...)]
    COMPARE_IN = 35,
    // NOT IN operator [left NOT IN (right1, right2, ...)]
    COMPARE_NOT_IN = 36,
    // IS DISTINCT FROM operator
    COMPARE_DISTINCT_FROM = 37,
    // compare final boundary

    COMPARE_BETWEEN = 38,
    COMPARE_NOT_BETWEEN = 39,
    COMPARE_BOUNDARY_END = COMPARE_NOT_BETWEEN,
};

struct Equals {
    template <class T> static inline bool Operation(T left, T right) {
        return left == right;
    }
};
struct NotEquals {
    template <class T> static inline bool Operation(T left, T right) {
        return left != right;
    }
};
struct GreaterThan {
    template <class T> static inline bool Operation(T left, T right) {
        return left > right;
    }
};
struct GreaterThanEquals {
    template <class T> static inline bool Operation(T left, T right) {
        return left >= right;
    }
};
struct LessThan {
    template <class T> static inline bool Operation(T left, T right) {
        return left < right;
    }
};
struct LessThanEquals {
    template <class T> static inline bool Operation(T left, T right) {
        return left <= right;
    }
};

struct AddOperator {
    template <class TA, class TB, class TR> static inline TR Operation(TA left, TB right) {
        return left + right;
    }
};

struct SubtractOperator {
    template <class TA, class TB, class TR> static inline TR Operation(TA left, TB right) {
        return left - right;
    }
};

struct MultiplyOperator {
    template <class TA, class TB, class TR> static inline TR Operation(TA left, TB right) {
        return left * right;
    }
};

struct DivideOperator {
    template <class TA, class TB, class TR> static inline TR Operation(TA left, TB right) {
        assert(right != 0); // this should be checked before!
        return left / right;
    }
};

struct ModuloOperator {
    template <class TA, class TB, class TR> static inline TR Operation(TA left, TB right) {
        assert(right != 0);
        return left % right;
    }
};

template <> float AddOperator::Operation(float left, float right);
template <> double AddOperator::Operation(double left, double right);
template <> float SubtractOperator::Operation(float left, float right);
template <> double SubtractOperator::Operation(double left, double right);
template <> float MultiplyOperator::Operation(float left, float right);
template <> double MultiplyOperator::Operation(double left, double right);
template <> float DivideOperator::Operation(float left, float right);
template <> double DivideOperator::Operation(double left, double right);
template <> float ModuloOperator::Operation(float left, float right);
template <> double ModuloOperator::Operation(double left, double right);