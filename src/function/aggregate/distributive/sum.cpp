#include "duckdb/function/aggregate/distributive_functions.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/null_value.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/common/vector_operations/aggregate_executor.hpp"
#include "duckdb/common/operator/numeric_binary_operators.hpp"

using namespace std;

namespace duckdb {

struct sum_state_t {
	double value;
	bool isset;
};

struct secure_sum_state_t {
    data_ptr_t secure_state;
};

struct SumOperation {
	template <class STATE> static void Initialize(STATE *state) {
		state->value = 0;
		state->isset = false;
	}

	template <class INPUT_TYPE, class STATE, class OP>
	static void Operation(STATE *state, INPUT_TYPE *input, nullmask_t &nullmask, idx_t idx) {
		state->isset = true;
		state->value += input[idx];
	}

	template <class INPUT_TYPE, class STATE, class OP>
	static void ConstantOperation(STATE *state, INPUT_TYPE *input, nullmask_t &nullmask, idx_t count) {
		state->isset = true;
		state->value += (double)input[0] * (double)count;
	}

	template <class T, class STATE>
	static void Finalize(Vector &result, STATE *state, T *target, nullmask_t &nullmask, idx_t idx) {
		if (!state->isset) {
			nullmask[idx] = true;
		} else {
			if (!Value::DoubleIsValid(state->value)) {
				throw OutOfRangeException("SUM is out of range!");
			}
			target[idx] = state->value;
		}
	}

	template <class STATE, class OP> static void Combine(STATE source, STATE *target) {
		if (!source.isset) {
			// source is NULL, nothing to do
			return;
		}
		if (!target->isset) {
			// target is NULL, use source value directly
			*target = source;
		} else {
			// else perform the operation
			target->value += source.value;
		}
	}

	static bool IgnoreNull() {
		return true;
	}
};

struct SecureSumOperation : SumOperation {
    template <class STATE> static void Initialize(STATE *state) {
        state->secure_state = EnclaveExecutor::CreateSecureAggregateState();
    }

    template <class INPUT_TYPE, class STATE, class OP>
    static void Operation(STATE *state, INPUT_TYPE *input, nullmask_t &nullmask, idx_t idx) {
        // Defined in enclave
    }

    template <class INPUT_TYPE, class STATE, class OP>
    static void ConstantOperation(STATE *state, INPUT_TYPE *input, nullmask_t &nullmask, idx_t count) {
        // Defined in enclave
    }

    template <class T, class STATE>
    static void Finalize(Vector &result, STATE *state, T *target, nullmask_t &nullmask, idx_t idx) {
        sum_state_t state_tmp;

        EnclaveExecutor::DecryptAggregateState((data_ptr_t)state, (data_ptr_t)&state_tmp);

        if (!state_tmp.isset) {
            nullmask[idx] = true;
        } else {

            if (!Value::DoubleIsValid(state_tmp.value)) {
                throw OutOfRangeException("SUM is out of range!");
            }
            target[idx] = state_tmp.value;
        }

        EnclaveExecutor::FreeSecureAggregateState((data_ptr_t)state);
    }

    template <class STATE, class OP> static void Combine(STATE source, STATE *target) {
        // Not used
	}
};

void SumFun::RegisterFunction(BuiltinFunctions &set) {
	AggregateFunctionSet sum("sum");
	// integer sums to bigint
	sum.AddFunction(AggregateFunction::UnaryAggregate<secure_sum_state_t, int32_t, double, SecureSumOperation>(SQLType::INTEGER,
	                                                                                              SQLType::DOUBLE));
	sum.AddFunction(AggregateFunction::UnaryAggregate<secure_sum_state_t, int64_t, double, SecureSumOperation>(SQLType::BIGINT,
	                                                                                              SQLType::DOUBLE));
	// float sums to float
	sum.AddFunction(
	    AggregateFunction::UnaryAggregate<secure_sum_state_t, double, double, SecureSumOperation>(SQLType::DOUBLE, SQLType::DOUBLE));

	set.AddFunction(sum);
}

} // namespace duckdb
