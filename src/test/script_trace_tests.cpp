// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/trace.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(script_trace_tests, BasicTestingSetup)

#ifdef ENABLE_SCRIPT_TRACE

namespace {
struct RecordedFrame {
    ScriptTraceFrameKind kind;
    uint8_t opcode;
    uint32_t opcode_pos;
    ScriptError script_error;
    std::vector<std::vector<unsigned char>> stack;
    std::vector<std::vector<unsigned char>> altstack;
    bool exec;
    uint32_t codeseparator_pos;
    int op_count;
    uint8_t sig_version;
    bool stack_data_is_null;
};

RecordedFrame Record(const ScriptTraceFrame& f)
{
    return RecordedFrame{
        .kind = f.kind,
        .opcode = f.opcode,
        .opcode_pos = f.opcode_pos,
        .script_error = f.script_error,
        .stack = {f.stack.begin(), f.stack.end()},
        .altstack = {f.altstack.begin(), f.altstack.end()},
        .exec = f.exec,
        .codeseparator_pos = f.codeseparator_pos,
        .op_count = f.op_count,
        .sig_version = f.sig_version,
        .stack_data_is_null = f.stack.data() == nullptr,
    };
}

struct TraceRecorder {
    std::vector<RecordedFrame> frames;

    TraceRecorder()
    {
        ScriptTraceRegisterCallback([this](const ScriptTraceFrame& f) { frames.push_back(Record(f)); });
    }
    ~TraceRecorder() { ScriptTraceRegisterCallback(nullptr); }
};
} // namespace

BOOST_AUTO_TEST_CASE(trace_records_each_opcode)
{
    TraceRecorder rec;

    // OP_1 OP_2 OP_ADD -> stack [3]
    const CScript script = CScript() << OP_1 << OP_2 << OP_ADD;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    BOOST_REQUIRE_EQUAL(rec.frames.size(), 5U); // Begin + 3 Step + End
    BOOST_CHECK(rec.frames.front().kind == ScriptTraceFrameKind::Begin);
    BOOST_CHECK(rec.frames.back().kind == ScriptTraceFrameKind::End);

    BOOST_CHECK_EQUAL(rec.frames[1].opcode, OP_1);
    BOOST_CHECK_EQUAL(rec.frames[2].opcode, OP_2);
    BOOST_CHECK_EQUAL(rec.frames[3].opcode, OP_ADD);

    // Stack snapshot is taken before the opcode executes.
    BOOST_CHECK_EQUAL(rec.frames[3].stack.size(), 2U);
    BOOST_CHECK_EQUAL(rec.frames.back().stack.size(), 1U);
    BOOST_CHECK_EQUAL(rec.frames.back().stack.at(0).at(0), 3);
    BOOST_CHECK_EQUAL(rec.frames.back().script_error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(trace_records_failing_script)
{
    TraceRecorder rec;

    const CScript script = CScript() << OP_ADD; // underflow: empty stack
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    BaseSignatureChecker checker;

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(rec.frames.back().script_error, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(trace_oversized_script_emits_no_frames)
{
    TraceRecorder rec;

    CScript script;
    script.assign(MAX_SCRIPT_SIZE + 1, OP_NOP);
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_OK};
    BaseSignatureChecker checker;

    BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SCRIPT_SIZE);

    // The size check returns before SCRIPT_TRACE_SCOPE is declared, so this evaluation
    // produces no Begin and no End frame at all -- a consumer pairing the two to delimit
    // evaluations never sees it.
    BOOST_CHECK_EQUAL(rec.frames.size(), 0U);
}

BOOST_AUTO_TEST_CASE(trace_reports_stack_and_altstack)
{
    TraceRecorder rec;

    const CScript script = CScript() << OP_1 << OP_2 << OP_TOALTSTACK << OP_3 << OP_FROMALTSTACK << OP_ADD;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Begin + 6 Step + End
    BOOST_REQUIRE_EQUAL(rec.frames.size(), 8U);

    const std::vector<unsigned char> one{1}, two{2}, three{3}, five{5};

    // Snapshots are taken before the opcode executes.
    const auto& at_toalt = rec.frames[3];
    BOOST_CHECK_EQUAL(at_toalt.opcode, OP_TOALTSTACK);
    BOOST_REQUIRE_EQUAL(at_toalt.stack.size(), 2U);
    BOOST_CHECK(at_toalt.stack[0] == one);
    BOOST_CHECK(at_toalt.stack[1] == two);
    BOOST_CHECK_EQUAL(at_toalt.altstack.size(), 0U);

    // OP_TOALTSTACK has run: the top element moved across.
    const auto& at_3 = rec.frames[4];
    BOOST_CHECK_EQUAL(at_3.opcode, OP_3);
    BOOST_REQUIRE_EQUAL(at_3.stack.size(), 1U);
    BOOST_CHECK(at_3.stack[0] == one);
    BOOST_REQUIRE_EQUAL(at_3.altstack.size(), 1U);
    BOOST_CHECK(at_3.altstack[0] == two);

    const auto& at_fromalt = rec.frames[5];
    BOOST_CHECK_EQUAL(at_fromalt.opcode, OP_FROMALTSTACK);
    BOOST_REQUIRE_EQUAL(at_fromalt.stack.size(), 2U);
    BOOST_CHECK(at_fromalt.stack[0] == one);
    BOOST_CHECK(at_fromalt.stack[1] == three);
    BOOST_REQUIRE_EQUAL(at_fromalt.altstack.size(), 1U);
    BOOST_CHECK(at_fromalt.altstack[0] == two);

    const auto& at_add = rec.frames[6];
    BOOST_CHECK_EQUAL(at_add.opcode, OP_ADD);
    BOOST_REQUIRE_EQUAL(at_add.stack.size(), 3U);
    BOOST_CHECK(at_add.stack[2] == two);
    BOOST_CHECK_EQUAL(at_add.altstack.size(), 0U);

    const auto& end = rec.frames.back();
    BOOST_REQUIRE_EQUAL(end.stack.size(), 2U);
    BOOST_CHECK(end.stack[0] == one);
    BOOST_CHECK(end.stack[1] == five);
    BOOST_CHECK_EQUAL(end.altstack.size(), 0U);
}

BOOST_AUTO_TEST_CASE(trace_reports_exec_false_in_untaken_branch)
{
    TraceRecorder rec;

    const CScript script = CScript() << OP_0 << OP_IF << OP_ADD << OP_ENDIF << OP_1;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Begin + 5 Step + End
    BOOST_REQUIRE_EQUAL(rec.frames.size(), 7U);

    // `exec` is sampled before the opcode runs, so OP_IF itself is still executing and
    // OP_ENDIF is still inside the untaken branch.
    BOOST_CHECK(rec.frames[0].exec);              // Begin
    BOOST_CHECK(rec.frames[1].exec);              // OP_0
    BOOST_CHECK(rec.frames[2].exec);              // OP_IF
    BOOST_CHECK(!rec.frames[3].exec);             // OP_ADD, not taken
    BOOST_CHECK_EQUAL(rec.frames[3].opcode, OP_ADD);
    BOOST_CHECK(!rec.frames[4].exec);             // OP_ENDIF
    BOOST_CHECK(rec.frames[5].exec);              // OP_1
    BOOST_CHECK(rec.frames[6].exec);              // End

    // The skipped OP_ADD did not touch the stack.
    BOOST_CHECK_EQUAL(rec.frames[3].stack.size(), 0U);
}

BOOST_AUTO_TEST_CASE(trace_reports_empty_stack_safely)
{
    TraceRecorder rec;

    const CScript script = CScript() << OP_1;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));

    BOOST_REQUIRE_GE(rec.frames.size(), 1U);
    // An empty span: .data() may legitimately be nullptr (it is here, since the vector
    // never allocated), so embedders must not dereference it without checking the size.
    BOOST_CHECK_EQUAL(rec.frames.front().stack.size(), 0U);
    BOOST_CHECK_EQUAL(rec.frames.front().altstack.size(), 0U);
    BOOST_CHECK(rec.frames.front().stack_data_is_null);
}

BOOST_AUTO_TEST_CASE(trace_callback_lifecycle)
{
    std::vector<RecordedFrame> first, second;
    ScriptTraceRegisterCallback([&first](const ScriptTraceFrame& f) { first.push_back(Record(f)); });

    const CScript script = CScript() << OP_1;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;
    {
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    }
    BOOST_CHECK_EQUAL(first.size(), 3U);

    // Registering replaces: only the new callback receives frames.
    ScriptTraceRegisterCallback([&second](const ScriptTraceFrame& f) { second.push_back(Record(f)); });
    {
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    }
    BOOST_CHECK_EQUAL(first.size(), 3U);
    BOOST_CHECK_EQUAL(second.size(), 3U);

    // Unregistering stops frames entirely.
    ScriptTraceRegisterCallback(nullptr);
    {
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    }
    BOOST_CHECK_EQUAL(first.size(), 3U);
    BOOST_CHECK_EQUAL(second.size(), 3U);

    // An empty std::function is equally a deregistration.
    ScriptTraceRegisterCallback(ScriptTraceCallback{});
    {
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    }
    BOOST_CHECK_EQUAL(second.size(), 3U);
}

BOOST_AUTO_TEST_CASE(trace_reports_codeseparator_pos)
{
    TraceRecorder rec;

    const CScript script = CScript() << OP_1 << OP_CODESEPARATOR << OP_2 << OP_CODESEPARATOR << OP_3;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
    BaseSignatureChecker checker;

    BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Begin + 5 Step + End
    BOOST_REQUIRE_EQUAL(rec.frames.size(), 7U);

    constexpr uint32_t NO_SEPARATOR{0xFFFFFFFFUL};

    // The hook fires after the opcode is decoded but before it is dispatched, so the Step
    // frame for an OP_CODESEPARATOR still reports the PREVIOUS separator position; the
    // update is only visible from the next frame onwards.
    BOOST_CHECK_EQUAL(rec.frames[0].codeseparator_pos, NO_SEPARATOR);
    BOOST_CHECK_EQUAL(rec.frames[1].codeseparator_pos, NO_SEPARATOR); // OP_1
    BOOST_CHECK_EQUAL(rec.frames[2].opcode, OP_CODESEPARATOR);
    BOOST_CHECK_EQUAL(rec.frames[2].codeseparator_pos, NO_SEPARATOR);
    BOOST_CHECK_EQUAL(rec.frames[3].codeseparator_pos, 1U); // OP_2, first separator applied
    BOOST_CHECK_EQUAL(rec.frames[4].opcode, OP_CODESEPARATOR);
    BOOST_CHECK_EQUAL(rec.frames[4].codeseparator_pos, 1U);
    BOOST_CHECK_EQUAL(rec.frames[5].codeseparator_pos, 3U); // OP_3
    BOOST_CHECK_EQUAL(rec.frames.back().codeseparator_pos, 3U);

    // opcode_pos indexes the opcode the Step frame is reporting on.
    BOOST_CHECK_EQUAL(rec.frames[2].opcode_pos, 1U);
    BOOST_CHECK_EQUAL(rec.frames[4].opcode_pos, 3U);
}

BOOST_AUTO_TEST_CASE(trace_end_frame_opcode_pos_is_ambiguous)
{
    const std::vector<unsigned char> one{1};
    BaseSignatureChecker checker;

    // opcode_pos is bound by reference to the loop counter, which is only incremented on a
    // normal iteration. If the loop reaches the end of the script the End frame reports the
    // opcode COUNT (one past the last index); if an opcode returns early it reports that
    // opcode's INDEX. The two are indistinguishable from the frame alone.
    //
    // The distinction is loop-exit vs early-return, NOT success vs failure: the checks after
    // the loop can fail with the counter already at the count, so script_error is not enough
    // to tell the two readings apart either.
    uint32_t pos_on_success{}, pos_on_failure{}, pos_on_post_loop_failure{};

    {
        TraceRecorder rec;
        const CScript script = CScript() << OP_1 << OP_2 << OP_ADD;
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err{SCRIPT_ERR_UNKNOWN_ERROR};
        BOOST_CHECK(EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

        pos_on_success = rec.frames.back().opcode_pos;
        BOOST_CHECK_EQUAL(pos_on_success, 3U); // three opcodes ran, valid indices are 0..2
    }

    {
        TraceRecorder rec;
        // OP_ADD at index 3 underflows: only one element on the stack.
        const CScript script = CScript() << OP_1 << OP_2 << OP_DROP << OP_ADD;
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);

        pos_on_failure = rec.frames.back().opcode_pos;
        BOOST_CHECK_EQUAL(pos_on_failure, 3U); // index of OP_ADD, which did NOT complete
    }

    {
        TraceRecorder rec;
        // The loop runs to the end, then the unbalanced-conditional check after it fails.
        const CScript script = CScript() << OP_1 << OP_IF << OP_2;
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err{SCRIPT_ERR_OK};
        BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

        pos_on_post_loop_failure = rec.frames.back().opcode_pos;
        BOOST_CHECK_EQUAL(pos_on_post_loop_failure, 3U); // the count, despite the failure
    }

    // Same value across all three: a successful script, one that aborted on its opcode at
    // that index, and one that failed only after the loop finished. opcode_pos alone cannot
    // distinguish them, and neither can opcode_pos together with script_error -- the two
    // failing cases carry different errors but opposite readings of the same number, and
    // the frame exposes no opcode count to compare opcode_pos against.
    BOOST_CHECK_EQUAL(pos_on_success, pos_on_failure);
    BOOST_CHECK_EQUAL(pos_on_success, pos_on_post_loop_failure);
}

#endif // ENABLE_SCRIPT_TRACE

BOOST_AUTO_TEST_SUITE_END()
