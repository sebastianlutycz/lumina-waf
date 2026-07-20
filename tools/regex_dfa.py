#!/usr/bin/env python3
"""Build-time regular-expression compiler for LuminaWAF.

The module lowers Python's parsed regular AST to a Thompson graph and then
determinizes it. It never executes in the request path. Generated runtimes use
only compact DFA transitions.
"""

from collections import deque
from dataclasses import dataclass, field
import re
import re._parser as reparser


ALL_BYTES = (1 << 256) - 1


@dataclass
class Edge:
    kind: str
    target: int
    mask: int = 0
    assertion: str = ""


@dataclass
class State:
    edges: list[Edge] = field(default_factory=list)


@dataclass
class Fragment:
    start: int
    end: int


class UnsupportedRegex(ValueError):
    pass


def inline_flag_enabled(pattern, flag):
    """Return whether a positive inline flag set enables `flag`.

    CRS primarily uses leading global/scoped groups. The byte compiler treats
    a leading scoped flag as applying to the generated matcher, matching the
    translator's established handling of `(?i:...)`.
    """
    for match in re.finditer(r"\(\?([a-zA-Z]*)(?:-[a-zA-Z]*)?[:)]", pattern):
        if flag in match.group(1).lower():
            return True
    return False


class ThompsonBuilder:
    def __init__(self, ignore_case=False, dot_all=False):
        self.states = []
        self.ignore_case = ignore_case
        self.dot_all = dot_all

    def state(self):
        self.states.append(State())
        return len(self.states) - 1

    def edge(self, source, kind, target, mask=0, assertion=""):
        self.states[source].edges.append(Edge(kind, target, mask, assertion))

    def literal_mask(self, value):
        if value >= 256:
            raise UnsupportedRegex("non-byte literal")
        mask = 1 << value
        if self.ignore_case and (ord("A") <= value <= ord("Z") or
                                 ord("a") <= value <= ord("z")):
            mask |= 1 << (value ^ 32)
        return mask

    def class_mask(self, nodes):
        negate = bool(nodes and nodes[0][0].name == "NEGATE")
        if negate:
            nodes = nodes[1:]
        mask = 0

        def add(value):
            nonlocal mask
            if value < 256:
                mask |= self.literal_mask(value)

        for node_type, value in nodes:
            name = node_type.name
            if name == "LITERAL":
                add(value)
            elif name == "RANGE":
                for byte in range(value[0], min(value[1], 255) + 1):
                    add(byte)
            elif name == "CATEGORY":
                categories = {
                    reparser.CATEGORY_SPACE: b" \t\r\n\v\f",
                    reparser.CATEGORY_DIGIT: bytes(range(ord("0"), ord("9") + 1)),
                    reparser.CATEGORY_WORD: bytes(range(ord("0"), ord("9") + 1))
                    + bytes(range(ord("A"), ord("Z") + 1))
                    + bytes(range(ord("a"), ord("z") + 1)) + b"_",
                }
                negated = {
                    reparser.CATEGORY_NOT_SPACE: reparser.CATEGORY_SPACE,
                    reparser.CATEGORY_NOT_DIGIT: reparser.CATEGORY_DIGIT,
                    reparser.CATEGORY_NOT_WORD: reparser.CATEGORY_WORD,
                }
                if value in negated:
                    positive = self.class_mask([(reparser.CATEGORY, negated[value])])
                    mask |= ALL_BYTES ^ positive
                elif value in categories:
                    for byte in categories[value]:
                        add(byte)
                else:
                    raise UnsupportedRegex(f"category {value}")
            else:
                raise UnsupportedRegex(f"class node {name}")
        return (ALL_BYTES ^ mask) if negate else mask

    def atom(self, node_type, value):
        name = node_type.name
        start, end = self.state(), self.state()
        if name == "LITERAL":
            self.edge(start, "BYTE", end, self.literal_mask(value))
        elif name == "NOT_LITERAL":
            self.edge(start, "BYTE", end, ALL_BYTES ^ self.literal_mask(value))
        elif name == "IN":
            self.edge(start, "BYTE", end, self.class_mask(value))
        elif name == "ANY":
            mask = ALL_BYTES if self.dot_all else ALL_BYTES ^ (1 << ord("\n"))
            self.edge(start, "BYTE", end, mask)
        elif name == "AT":
            assertions = {
                "AT_BEGINNING": "BOL", "AT_BEGINNING_STRING": "BOL",
                "AT_END": "EOL", "AT_END_STRING": "EOL",
                "AT_BOUNDARY": "WB", "AT_NON_BOUNDARY": "NWB",
            }
            assertion = assertions.get(value.name)
            if not assertion:
                raise UnsupportedRegex(f"assertion {value.name}")
            self.edge(start, "ASSERT", end, assertion=assertion)
        elif name == "SUBPATTERN":
            return self.sequence(value[3])
        elif name == "BRANCH":
            for alternative in value[1]:
                fragment = self.sequence(alternative)
                self.edge(start, "EPS", fragment.start)
                self.edge(fragment.end, "EPS", end)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            return self.repeat(value[0], value[1], value[2])
        else:
            raise UnsupportedRegex(f"node {name}")
        return Fragment(start, end)

    def sequence(self, nodes):
        start = self.state()
        tail = start
        for node_type, value in nodes:
            fragment = self.atom(node_type, value)
            self.edge(tail, "EPS", fragment.start)
            tail = fragment.end
        end = self.state()
        self.edge(tail, "EPS", end)
        return Fragment(start, end)

    def repeat(self, minimum, maximum, inner):
        start = self.state()
        tail = start
        for _ in range(int(minimum)):
            fragment = self.sequence(inner)
            self.edge(tail, "EPS", fragment.start)
            tail = fragment.end
        end = self.state()
        unbounded = maximum == reparser.MAXREPEAT or int(maximum) >= 0xFFFFFFFF
        if unbounded:
            loop = self.sequence(inner)
            self.edge(tail, "EPS", end)
            self.edge(tail, "EPS", loop.start)
            self.edge(loop.end, "EPS", tail)
        else:
            optional = int(maximum) - int(minimum)
            if optional > 32:
                raise UnsupportedRegex("bounded repeat expansion exceeds 32")
            for _ in range(optional):
                fragment = self.sequence(inner)
                self.edge(tail, "EPS", fragment.start)
                self.edge(tail, "EPS", fragment.end)
                tail = fragment.end
            self.edge(tail, "EPS", end)
        return Fragment(start, end)


def _word(byte):
    return ord("0") <= byte <= ord("9") or ord("A") <= byte <= ord("Z") or \
        ord("a") <= byte <= ord("z") or byte == ord("_")


def requires_dfa(pattern):
    """True when greedy procedural emission cannot preserve continuation semantics."""
    normalized = re.sub(r"\(\?[a-zA-Z-]*\)", "", pattern)
    normalized = re.sub(r"\\x\{([0-9a-fA-F]{1,4})\}",
                        lambda m: chr(int(m.group(1), 16)), normalized).replace(r"\z", r"\Z")
    ast = reparser.parse(normalized)

    def contains_branch(nodes):
        for node_type, value in nodes:
            name = node_type.name
            if name == "BRANCH":
                return True
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                if contains_branch(value[2]):
                    return True
            elif name == "SUBPATTERN" and contains_branch(value[3]):
                return True
        return False

    def walk(nodes):
        for index, (node_type, value) in enumerate(nodes):
            name = node_type.name
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                if int(value[1]) != int(value[0]) and index + 1 < len(nodes):
                    return True
                # The procedural emitter cannot backtrack into an optional
                # nested alternation when the zero-width path is accepted.
                # Determinize this shape even when the repeat is terminal.
                if int(value[1]) != int(value[0]) and contains_branch(value[2]):
                    return True
                if walk(value[2]):
                    return True
            elif name == "SUBPATTERN" and walk(value[3]):
                return True
            elif name == "BRANCH" and any(walk(alt) for alt in value[1]):
                return True
        return False

    return walk(ast)


def parse_regex_ast(pattern):
    """Parse one regular expression into the build-time AST and global flags."""
    ignore_case = inline_flag_enabled(pattern, "i")
    dot_all = inline_flag_enabled(pattern, "s")
    normalized = re.sub(r"\(\?[a-zA-Z-]*\)", "", pattern)
    normalized = re.sub(r"\\x\{([0-9a-fA-F]{1,4})\}",
                        lambda m: chr(int(m.group(1), 16)), normalized)
    normalized = normalized.replace(r"\z", r"\Z")
    return reparser.parse(normalized), ignore_case, dot_all


def compile_dfa_ast(ast, ignore_case=False, dot_all=False, state_budget=65535):
    """Determinize an already parsed AST fragment at translation time."""
    builder = ThompsonBuilder(ignore_case, dot_all)
    fragment = builder.sequence(ast)

    byte_edges = [edge.mask for state in builder.states for edge in state.edges if edge.kind == "BYTE"]
    signatures = {}
    for byte in range(256):
        signature = (_word(byte), tuple(bool(mask & (1 << byte)) for mask in byte_edges))
        signatures.setdefault(signature, []).append(byte)
    classes = list(signatures.values())
    byte_class = [0] * 256
    for class_id, members in enumerate(classes):
        for byte in members:
            byte_class[byte] = class_id

    def assertion_ok(name, previous_word, current_word, bol, eol):
        return {"BOL": bol, "EOL": eol, "WB": previous_word != current_word,
                "NWB": previous_word == current_word}[name]

    import functools
    @functools.lru_cache(None)
    def closure(seed, previous_word=None, current_word=None, bol=False, eol=False, contextual=False):
        result = set(seed)
        queue = list(seed)
        while queue:
            index = queue.pop()
            for edge in builder.states[index].edges:
                follow = edge.kind == "EPS"
                if contextual and edge.kind == "ASSERT":
                    follow = assertion_ok(edge.assertion, previous_word, current_word, bol, eol)
                if follow and edge.target not in result:
                    result.add(edge.target)
                    queue.append(edge.target)
        return frozenset(result)

    start_set = closure(frozenset({fragment.start}))
    states = [start_set]
    state_ids = {start_set: 0}
    queue = deque([0])
    transitions, accepts = [], []
    symbol_count = len(classes) * 4
    while queue:
        state_id = queue.popleft()
        state_set = states[state_id]
        row, accept_row = [0] * symbol_count, [False] * symbol_count
        for bol in (False, True):
            for previous_word in (False, True):
                for class_id, members in enumerate(classes):
                    byte = members[0]
                    symbol = class_id + len(classes) * (int(previous_word) + 2 * int(bol))
                    expanded = closure(state_set, previous_word, _word(byte), bol, False, True)
                    accept_row[symbol] = fragment.end in expanded
                    destinations = set()
                    for index in expanded:
                        for edge in builder.states[index].edges:
                            if edge.kind == "BYTE" and edge.mask & (1 << byte):
                                destinations.add(edge.target)
                    destination = closure(frozenset(destinations))
                    if destination not in state_ids:
                        if len(states) >= state_budget:
                            raise UnsupportedRegex(f"DFA state budget {state_budget} exceeded")
                        state_ids[destination] = len(states)
                        states.append(destination)
                        queue.append(state_ids[destination])
                    row[symbol] = state_ids[destination]
        transitions.append(row)
        accepts.append(accept_row)

    eof_accept = []
    for state_set in states:
        contexts = []
        for bol in (False, True):
            for previous_word in (False, True):
                expanded = closure(state_set, previous_word, False, bol, True, True)
                contexts.append(fragment.end in expanded)
        eof_accept.append(contexts)
    return {
        "state_count": len(states), "class_count": len(classes), "symbol_count": symbol_count,
        "byte_class": byte_class, "transitions": transitions, "accepts": accepts,
        "eof_accept": eof_accept, "nfa_state_count": len(builder.states),
        "dead_state": state_ids.get(frozenset(), -1),
    }


def compile_dfa(pattern, state_budget=65535):
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    return compile_dfa_ast(ast, ignore_case, dot_all, state_budget)


def _unwrap_single_subpattern(ast):
    """Remove transparent one-node groups for structural build-time analysis."""
    current = ast
    while (len(current) == 1 and current[0][0].name == "SUBPATTERN"):
        current = current[0][1][3]
    return current


def _mandatory_literal_runs(ast):
    """Return byte strings guaranteed on every path through this AST fragment.

    This is intentionally conservative. Unknown consumers, assertions and
    optional repeats contribute no literals. A branch contributes only exact
    literal runs present in every alternative.
    """
    ast = _unwrap_single_subpattern(ast)
    guaranteed = set()
    literal_run = bytearray()

    def flush_literal_run():
        if literal_run:
            guaranteed.add(bytes(literal_run))
            literal_run.clear()

    for node_type, value in ast:
        name = node_type.name
        if name == "LITERAL" and 0 <= int(value) < 256:
            literal_run.append(int(value))
            continue

        flush_literal_run()
        if name == "SUBPATTERN":
            guaranteed.update(_mandatory_literal_runs(value[3]))
        elif name == "BRANCH":
            alternatives = [
                _mandatory_literal_runs(alternative)
                for alternative in value[1]
            ]
            if alternatives:
                common = set(alternatives[0])
                for alternative in alternatives[1:]:
                    common.intersection_update(alternative)
                guaranteed.update(common)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            minimum = int(value[0])
            if minimum > 0:
                guaranteed.update(_mandatory_literal_runs(value[2]))

    flush_literal_run()
    return guaranteed


def compile_seeded_fast_accept_branches(
        pattern, state_budget=128, table_budget=64 * 1024,
        min_seed_len=4, max_branches=4):
    """Plan exact seeded branch DFAs for a large alternation.

    Every selected seed is proven mandatory for its top-level alternative.
    Seed hits are only candidate signals; the returned DFA includes an exact
    all-byte search prefix and remains the acceptance authority.
    """
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    root = _unwrap_single_subpattern(ast)
    if len(root) != 1 or root[0][0].name != "BRANCH":
        return []

    prefix_ast, _, _ = parse_regex_ast(r"(?:[\x00-\xff]*)")
    plans = []
    for alternative_index, alternative in enumerate(root[0][1][1]):
        candidates = [
            literal for literal in _mandatory_literal_runs(alternative)
            if len(literal) >= min_seed_len
        ]
        if not candidates:
            continue
        seed = max(candidates, key=lambda value: (len(value), value))
        if ignore_case:
            seed = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in seed
            )
        search_ast = reparser.SubPattern(
            ast.state, list(prefix_ast.data) + list(alternative.data))
        try:
            dfa = compile_dfa_ast(
                search_ast, ignore_case, dot_all,
                state_budget=state_budget)
            # Reuse the production emitter's exact row-interned size check.
            emit_dfa_c(
                0, None,
                state_budget=state_budget,
                table_budget=table_budget,
                function_name="lumina_seed_plan_probe",
                symbol_prefix="lumina_seed_plan_probe_data",
                match_value=1,
                static_function=True,
                compiled_dfa=dfa,
                intern_transition_rows=True,
                intern_accept_rows=True,
            )
        except UnsupportedRegex:
            continue
        plans.append({
            "alternative_index": alternative_index,
            "seed": seed,
            "ignore_case": ignore_case,
            "dfa": dfa,
        })
        if len(plans) >= max_branches:
            break
    return plans


def compile_mandatory_seed_cover(pattern, min_seed_len=1, max_seeds=16):
    """Return a sound union of literals covering every top-level alternative.

    A value that contains none of the returned literals cannot match the
    expression. A positive seed hit is only a candidate and must still enter
    the exact matcher.
    """
    ast, ignore_case, _ = parse_regex_ast(pattern)
    root = _unwrap_single_subpattern(ast)
    if len(root) == 1 and root[0][0].name == "BRANCH":
        alternatives = root[0][1][1]
    else:
        alternatives = (root,)

    selected = []
    for alternative in alternatives:
        candidates = [
            literal for literal in _mandatory_literal_runs(alternative)
            if len(literal) >= min_seed_len
        ]
        if not candidates:
            return None
        seed = max(candidates, key=lambda value: (len(value), value))
        if ignore_case:
            seed = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in seed
            )
        selected.append(seed)

    seeds = tuple(sorted(set(selected)))
    if not seeds or len(seeds) > max_seeds:
        return None
    return {"seeds": seeds, "ignore_case": ignore_case}


def dfa_match(dfa, data, offset=0):
    """Build-time reference executor used only by translator unit tests."""
    if isinstance(data, str):
        data = data.encode("latin1")
    state = 0
    previous_word = offset > 0 and _word(data[offset - 1])
    bol = offset == 0
    class_count = dfa["class_count"]
    for byte in data[offset:]:
        symbol = dfa["byte_class"][byte] + class_count * (int(previous_word) + 2 * int(bol))
        if dfa["accepts"][state][symbol]:
            return True
        state = dfa["transitions"][state][symbol]
        previous_word = _word(byte)
        bol = False
    return dfa["eof_accept"][state][int(previous_word) + 2 * int(bol)]


def emit_dfa_c(rule_id, pattern, state_budget=65535, table_budget=2 * 1024 * 1024,
               function_name=None, symbol_prefix=None, match_value=None,
               static_function=False, report_match_end=False,
               longest_match_end=False, stop_on_dead=True,
               ascii_lower_input=False, ast=None, ast_ignore_case=False,
               ast_dot_all=False, compiled_dfa=None, accept_delegate=None,
               accept_delegate_tristate=None, intern_transition_rows=False,
               intern_accept_rows=False):
    """Emit one native DFA matcher.

    Custom symbols let the translator compose several private predicates into
    one public SecRule function, for example a same-buffer ModSecurity chain.
    The generated request-time code remains a table walker; composition does
    not introduce a regex or NFA interpreter. Walkers terminate immediately
    after entering an absorbing dead state because no accepted state remains
    reachable from that point.
    """
    if report_match_end and (accept_delegate or accept_delegate_tristate):
        raise UnsupportedRegex("accept delegation cannot report one match endpoint")
    if accept_delegate and accept_delegate_tristate:
        raise UnsupportedRegex("boolean and tristate accept delegates are mutually exclusive")
    if compiled_dfa is not None:
        dfa = compiled_dfa
    elif ast is not None:
        dfa = compile_dfa_ast(ast, ast_ignore_case, ast_dot_all,
                              state_budget=state_budget)
    else:
        dfa = compile_dfa(pattern, state_budget=state_budget)
    states, symbols = dfa["state_count"], dfa["symbol_count"]

    def intern_rows(source_rows, enabled):
        if not enabled:
            return source_rows, None
        row_ids = {}
        unique_rows = []
        indices = []
        for source_row in source_rows:
            row = tuple(source_row)
            row_id = row_ids.get(row)
            if row_id is None:
                row_id = len(unique_rows)
                row_ids[row] = row_id
                unique_rows.append(source_row)
            indices.append(row_id)
        if len(unique_rows) >= len(source_rows):
            return source_rows, None
        return unique_rows, indices

    transition_rows, transition_row_index = intern_rows(
        dfa["transitions"], intern_transition_rows)
    accept_rows, accept_row_index = intern_rows(
        dfa["accepts"], intern_accept_rows)
    eof_rows, eof_row_index = intern_rows(
        dfa["eof_accept"], intern_accept_rows)

    transition_width = 2 if states <= 65535 else 4
    transition_index_width = (
        0 if transition_row_index is None else
        (2 if len(transition_rows) <= 65535 else 4))
    accept_index_width = (
        0 if accept_row_index is None else
        (1 if len(accept_rows) <= 255 else
         (2 if len(accept_rows) <= 65535 else 4)))
    eof_index_width = (
        0 if eof_row_index is None else
        (1 if len(eof_rows) <= 255 else
         (2 if len(eof_rows) <= 65535 else 4)))
    transition_bytes = (
        len(transition_rows) * symbols * transition_width +
        states * transition_index_width)
    accept_bytes = (
        len(accept_rows) * symbols + states * accept_index_width +
        len(eof_rows) * 4 + states * eof_index_width)
    if transition_bytes + accept_bytes > table_budget:
        raise UnsupportedRegex("DFA table budget exceeded")

    def rows(values, width=16):
        return "\n".join("    " + ",".join(str(v) for v in values[i:i + width]) + ","
                         for i in range(0, len(values), width))

    transition_type = "uint16_t" if states <= 65535 else "uint32_t"
    transitions = [value for row in transition_rows for value in row]
    accepts = [int(value) for row in accept_rows for value in row]
    eof_accepts = [int(value) for row in eof_rows for value in row]
    prefix = symbol_prefix or f"lumina_dfa_{rule_id}"
    function_name = function_name or f"lumina_scan_rule_{rule_id}"
    match_value = rule_id if match_value is None else match_value
    linkage = "static " if static_function else ""
    end_argument = ", size_t *match_end" if report_match_end else ""

    def index_type(row_count):
        if row_count <= 255:
            return "uint8_t"
        if row_count <= 65535:
            return "uint16_t"
        return "uint32_t"

    transition_index_decl = ""
    transition_row_expr = "state"
    if transition_row_index is not None:
        transition_index_decl = f"""
static const {index_type(len(transition_rows))} {prefix}_transition_row[{states}] = {{
{rows(transition_row_index)}
}};
"""
        transition_row_expr = f"{prefix}_transition_row[state]"

    accept_index_decl = ""
    accept_row_expr = "state"
    if accept_row_index is not None:
        accept_index_decl = f"""
static const {index_type(len(accept_rows))} {prefix}_accept_row[{states}] = {{
{rows(accept_row_index)}
}};
"""
        accept_row_expr = f"{prefix}_accept_row[state]"

    eof_index_decl = ""
    eof_row_expr = "state"
    if eof_row_index is not None:
        eof_index_decl = f"""
static const {index_type(len(eof_rows))} {prefix}_eof_row[{states}] = {{
{rows(eof_row_index)}
}};
"""
        eof_row_expr = f"{prefix}_eof_row[state]"

    accept_expr = f"{prefix}_accept[{accept_row_expr} * {symbols}u + symbol]"
    eof_expr = f"{prefix}_eof[{eof_row_expr} * 4u + previous_word + 2u * bol]"
    dead_action = ""
    if stop_on_dead and dfa["dead_state"] >= 0:
        dead_action = f"\n        if (state == {dfa['dead_state']}u) break;"
    if accept_delegate_tristate:
        accept_action = (
            f"if ({accept_expr}) {{ int delegated = "
            f"{accept_delegate_tristate}(data, len, pos); "
            f"if (delegated > 0) return {match_value}; "
            f"if (delegated < 0) return 0; }}"
        )
        eof_action = (
            f"if ({eof_expr}) {{ int delegated = "
            f"{accept_delegate_tristate}(data, len, len); "
            f"if (delegated > 0) return {match_value}; "
            f"if (delegated < 0) return 0; }}"
        )
        capture_state = ""
    elif accept_delegate:
        accept_action = (
            f"if ({accept_expr} && {accept_delegate}(data, len, pos)) "
            f"return {match_value};"
        )
        eof_action = (
            f"if ({eof_expr} && {accept_delegate}(data, len, len)) "
            f"return {match_value};"
        )
        capture_state = ""
    elif report_match_end and longest_match_end:
        accept_action = f"if ({accept_expr}) {{ found = 1; accepted_end = pos; }}"
        eof_action = (
            f"if ({eof_expr}) {{ found = 1; accepted_end = len; }}\n"
            f"    if (found) {{ if (match_end) *match_end = accepted_end; return {match_value}; }}"
        )
        capture_state = "    int found = 0;\n    size_t accepted_end = offset;\n"
    elif report_match_end:
        accept_action = f"if ({accept_expr}) {{ if (match_end) *match_end = pos; return {match_value}; }}"
        eof_action = f"if ({eof_expr}) {{ if (match_end) *match_end = len; return {match_value}; }}"
        capture_state = ""
    else:
        accept_action = f"if ({accept_expr}) return {match_value};"
        eof_action = f"if ({eof_expr}) return {match_value};"
        capture_state = ""
    return f"""
static const uint8_t {prefix}_class[256] = {{
{rows(dfa['byte_class'])}
}};
static const {transition_type} {prefix}_transition[{len(transitions)}] = {{
{rows(transitions)}
}};
{transition_index_decl}
static const uint8_t {prefix}_accept[{len(accepts)}] = {{
{rows(accepts)}
}};
{accept_index_decl}
static const uint8_t {prefix}_eof[{len(eof_accepts)}] = {{
{rows(eof_accepts)}
}};
{eof_index_decl}
{linkage}int {function_name}(const unsigned char *data, size_t len, size_t offset{end_argument}) {{
    uint32_t state = 0;
{capture_state}    
    uint32_t previous_word = offset > 0 && ((data[offset-1] >= '0' && data[offset-1] <= '9') ||
        (data[offset-1] >= 'A' && data[offset-1] <= 'Z') ||
        (data[offset-1] >= 'a' && data[offset-1] <= 'z') || data[offset-1] == '_');
    uint32_t bol = offset == 0;
    for (size_t pos = offset; pos < len; pos++) {{
        unsigned char input_byte = data[pos];
        {"if (input_byte >= 'A' && input_byte <= 'Z') input_byte |= 0x20u;" if ascii_lower_input else ""}
        uint32_t symbol = {prefix}_class[input_byte] + {dfa['class_count']}u * (previous_word + 2u * bol);
        {accept_action}
        state = {prefix}_transition[{transition_row_expr} * {symbols}u + symbol];{dead_action}
        unsigned char byte = input_byte;
        previous_word = (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= 'a' && byte <= 'z') || byte == '_';
        bol = 0;
    }}
    {eof_action}
    return 0;
}}
"""

def compile_bitset_nfa_ast(ast, ignore_case=False, dot_all=False,
                           state_budget=512, word_budget=8,
                           vector_budget=255,
                           table_budget=256 * 1024):
    """Compile a bounded Thompson graph into interned multiword transitions."""
    builder = ThompsonBuilder(ignore_case, dot_all)
    fragment = builder.sequence(ast)

    state_count = len(builder.states)
    word_count = (state_count + 63) // 64
    if state_count > state_budget:
        raise UnsupportedRegex(f"NFA state budget {state_budget} exceeded")
    if word_count > word_budget:
        raise UnsupportedRegex(f"NFA word budget {word_budget} exceeded")

    byte_edges = [edge.mask for state in builder.states
                  for edge in state.edges if edge.kind == "BYTE"]
    signatures = {}
    for byte in range(256):
        signature = (_word(byte),
                     tuple(bool(mask & (1 << byte)) for mask in byte_edges))
        signatures.setdefault(signature, []).append(byte)
    classes = list(signatures.values())
    byte_class = [0] * 256
    for class_id, members in enumerate(classes):
        for byte in members:
            byte_class[byte] = class_id

    def assertion_ok(name, previous_word, current_word, bol, eol):
        return {"BOL": bol, "EOL": eol, "WB": previous_word != current_word,
                "NWB": previous_word == current_word}[name]

    import functools

    @functools.lru_cache(None)
    def closure(seed, previous_word=None, current_word=None,
                bol=False, eol=False, contextual=False):
        result = set(seed)
        queue = list(seed)
        while queue:
            index = queue.pop()
            for edge in builder.states[index].edges:
                follow = edge.kind == "EPS"
                if contextual and edge.kind == "ASSERT":
                    follow = assertion_ok(
                        edge.assertion, previous_word, current_word, bol, eol)
                if follow and edge.target not in result:
                    result.add(edge.target)
                    queue.append(edge.target)
        return frozenset(result)

    def state_mask(states):
        mask = 0
        for state in states:
            mask |= 1 << state
        return mask

    symbol_count = len(classes) * 4
    empty_mask = 0
    vector_ids = {empty_mask: 0}
    vectors = [empty_mask]
    transition_ids = []
    accept_masks = []
    source_masks = []

    # Symbol-major storage keeps the current byte/context row contiguous.
    for bol in (False, True):
        for previous_word in (False, True):
            for members in classes:
                byte = members[0]
                accept_mask = 0
                symbol_transitions = []
                for state_index in range(state_count):
                    expanded = closure(
                        frozenset({state_index}), previous_word, _word(byte),
                        bol, False, True)
                    if fragment.end in expanded:
                        accept_mask |= 1 << state_index
                    destinations = set()
                    for expanded_index in expanded:
                        for edge in builder.states[expanded_index].edges:
                            if edge.kind == "BYTE" and edge.mask & (1 << byte):
                                destinations.add(edge.target)
                    destination_mask = state_mask(
                        closure(frozenset(destinations)))
                    vector_id = vector_ids.get(destination_mask)
                    if vector_id is None:
                        if len(vectors) >= vector_budget:
                            raise UnsupportedRegex(
                                f"NFA vector budget {vector_budget} exceeded")
                        vector_id = len(vectors)
                        vector_ids[destination_mask] = vector_id
                        vectors.append(destination_mask)
                    symbol_transitions.append(vector_id)
                transition_ids.extend(symbol_transitions)
                accept_masks.append(accept_mask)
                source_mask = 0
                for state_index, vector_id in enumerate(symbol_transitions):
                    if vector_id:
                        source_mask |= 1 << state_index
                source_masks.append(source_mask)

    eof_masks = []
    for bol in (False, True):
        for previous_word in (False, True):
            accepting = set()
            for state_index in range(state_count):
                expanded = closure(
                    frozenset({state_index}), previous_word, False,
                    bol, True, True)
                if fragment.end in expanded:
                    accepting.add(state_index)
            eof_masks.append(state_mask(accepting))

    start_mask = state_mask(closure(frozenset({fragment.start})))
    vector_id_width = 1 if len(vectors) <= 255 else 2
    table_bytes = (
        256 +
        len(transition_ids) * vector_id_width +
        len(vectors) * word_count * 8 +
        len(accept_masks) * word_count * 8 +
        len(source_masks) * word_count * 8 +
        len(eof_masks) * word_count * 8 +
        word_count * 8
    )
    if table_bytes > table_budget:
        raise UnsupportedRegex(
            f"NFA table budget exceeded ({table_bytes} > {table_budget})")

    def split_words(mask):
        return [(mask >> (word * 64)) & 0xFFFFFFFFFFFFFFFF
                for word in range(word_count)]

    return {
        "state_count": state_count,
        "word_count": word_count,
        "class_count": len(classes),
        "symbol_count": symbol_count,
        "byte_class": byte_class,
        "transition_ids": transition_ids,
        "vectors": [split_words(mask) for mask in vectors],
        "accept_masks": [split_words(mask) for mask in accept_masks],
        "source_masks": [split_words(mask) for mask in source_masks],
        "eof_masks": [split_words(mask) for mask in eof_masks],
        "start_mask": split_words(start_mask),
        "vector_count": len(vectors),
        "table_bytes": table_bytes,
    }


def compile_bitset_nfa(pattern, state_budget=512, word_budget=8,
                       vector_budget=255, table_budget=256 * 1024):
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    return compile_bitset_nfa_ast(
        ast, ignore_case, dot_all,
        state_budget=state_budget,
        word_budget=word_budget,
        vector_budget=vector_budget,
        table_budget=table_budget,
    )


def bitset_nfa_match(nfa, data, offset=0):
    """Build-time reference executor used by differential unit tests."""
    if isinstance(data, str):
        data = data.encode("latin1")
    active = list(nfa["start_mask"])
    previous_word = offset > 0 and _word(data[offset - 1])
    bol = offset == 0
    words = nfa["word_count"]
    states = nfa["state_count"]
    for byte in data[offset:]:
        symbol = (nfa["byte_class"][byte] +
                  nfa["class_count"] * (int(previous_word) + 2 * int(bol)))
        accept = nfa["accept_masks"][symbol]
        if any(active[word] & accept[word] for word in range(words)):
            return True
        seen = set()
        base = symbol * states
        for word_index, active_word in enumerate(active):
            current = active_word
            while current:
                bit = (current & -current).bit_length() - 1
                current &= current - 1
                state = word_index * 64 + bit
                if state < states:
                    vector_id = nfa["transition_ids"][base + state]
                    if vector_id:
                        seen.add(vector_id)
        active = [0] * words
        for vector_id in seen:
            vector = nfa["vectors"][vector_id]
            for word in range(words):
                active[word] |= vector[word]
        if not any(active):
            return False
        previous_word = _word(byte)
        bol = False
    eof = nfa["eof_masks"][int(previous_word) + 2 * int(bol)]
    return any(active[word] & eof[word] for word in range(words))


def emit_bitset_nfa_c(rule_id, pattern, state_budget=512, word_budget=8,
                      vector_budget=255, table_budget=256 * 1024,
                      function_name=None, symbol_prefix=None,
                      match_value=None, static_function=False,
                      ascii_lower_input=False, ast=None,
                      ast_ignore_case=False, ast_dot_all=False,
                      fast_accept_plan=None,
                      fast_accept_table_budget=64 * 1024,
                      fast_accept_scan_budget=64,
                      mandatory_seed_cover=None):
    """Emit an exact bounded multiword NFA with interned destination vectors."""
    if ast is None:
        ast, ast_ignore_case, ast_dot_all = parse_regex_ast(pattern)
    nfa = compile_bitset_nfa_ast(
        ast, ast_ignore_case, ast_dot_all,
        state_budget=state_budget,
        word_budget=word_budget,
        vector_budget=vector_budget,
        table_budget=table_budget,
    )
    prefix = symbol_prefix or f"lumina_nfa_{rule_id}"
    fn_name = function_name or f"lumina_scan_rule_{rule_id}"
    match_value = rule_id if match_value is None else match_value
    linkage = "static " if static_function else ""

    def rows(values, width=8, hex_fmt=True):
        lines = []
        for i in range(0, len(values), width):
            if hex_fmt:
                chunk = [f"0x{x:x}ULL" for x in values[i:i + width]]
            else:
                chunk = [str(x) for x in values[i:i + width]]
            lines.append("    " + ", ".join(chunk) + ",")
        return "\n".join(lines)

    flat_vectors = [word for vector in nfa["vectors"] for word in vector]
    flat_accepts = [word for mask in nfa["accept_masks"] for word in mask]
    flat_sources = [word for mask in nfa["source_masks"] for word in mask]
    flat_eof = [word for mask in nfa["eof_masks"] for word in mask]
    seen_words = (nfa["vector_count"] + 63) // 64
    lower_code = (
        "if (input_byte >= 'A' && input_byte <= 'Z') input_byte |= 0x20u;"
        if ascii_lower_input else "")

    fast_helpers = []
    fast_entry = ""
    mandatory_seed_entry = ""
    if mandatory_seed_cover:
        seed_cases = {}
        ignore_case = mandatory_seed_cover["ignore_case"]
        for seed in mandatory_seed_cover["seeds"]:
            first = seed[0]
            labels = [first]
            if ignore_case and ord("a") <= first <= ord("z"):
                labels.append(first ^ 0x20)
            conditions = [f"pos + {len(seed)}u <= len"]
            for index, expected in enumerate(seed[1:], 1):
                byte_expr = f"data[pos + {index}u]"
                if ignore_case and ord("a") <= expected <= ord("z"):
                    conditions.append(
                        f"({byte_expr} == {expected}u || "
                        f"{byte_expr} == {expected ^ 0x20}u)")
                else:
                    conditions.append(f"{byte_expr} == {expected}u")
            statement = f"            if ({' && '.join(conditions)}) return 1;"
            for label in labels:
                seed_cases.setdefault(label, []).append(statement)

        case_code = []
        for first, statements in sorted(seed_cases.items()):
            case_code.append(
                f"        case {first}u:\n" + "\n".join(dict.fromkeys(statements)) +
                "\n            break;")
        fast_helpers.append(f"""
static int {prefix}_mandatory_seed_present(
        const unsigned char *data, size_t len, size_t offset) {{
    for (size_t pos = offset; pos < len; pos++) {{
        switch (data[pos]) {{
{chr(10).join(case_code)}
        default:
            break;
        }}
    }}
    return 0;
}}
""")
        mandatory_seed_entry = (
            f"    if (!{prefix}_mandatory_seed_present(data, len, offset)) return 0;\n")

    if fast_accept_plan:
        router_ignore_case = all(
            plan["ignore_case"] for plan in fast_accept_plan)
        grouped = {}
        all_hits = 0
        for ordinal, plan in enumerate(fast_accept_plan):
            helper = f"{prefix}_fast_{ordinal}"
            fast_helpers.append(emit_dfa_c(
                rule_id, None,
                table_budget=fast_accept_table_budget,
                function_name=helper,
                symbol_prefix=f"{prefix}_fast_{ordinal}_dfa",
                match_value=1,
                static_function=True,
                compiled_dfa=plan["dfa"],
                intern_transition_rows=True,
                intern_accept_rows=True,
            ))
            bit = 1 << ordinal
            all_hits |= bit
            grouped.setdefault(
                (plan["seed"], plan["ignore_case"]), []).append((bit, helper))

        cases = {}
        for (seed, ignore_case), helpers in grouped.items():
            first = seed[0]
            if ignore_case and ord("A") <= first <= ord("Z"):
                first |= 0x20
            conditions = [f"pos + {len(seed)}u <= len"]
            for index, expected in enumerate(seed[1:], 1):
                expression = f"data[pos + {index}u]"
                if ignore_case:
                    expression = f"{prefix}_ascii_lower({expression})"
                    if ord("A") <= expected <= ord("Z"):
                        expected |= 0x20
                conditions.append(f"{expression} == {expected}u")
            hit_mask = sum(bit for bit, _ in helpers)
            cases.setdefault(first, []).append(
                f"            if ({' && '.join(conditions)}) "
                f"seed_candidates |= 0x{hit_mask:x}u;")

        case_code = []
        for first, statements in sorted(cases.items()):
            labels = f"        case {first}u:"
            if (router_ignore_case and
                    ord("a") <= first <= ord("z")):
                labels += f"\n        case {first ^ 0x20}u:"
            case_code.append(
                labels + "\n" + "\n".join(statements) +
                "\n            break;")
        dispatch = []
        for ordinal, plan in enumerate(fast_accept_plan):
            helper = f"{prefix}_fast_{ordinal}"
            dispatch.append(
                f"            if ((seed_candidates & 0x{1 << ordinal:x}u) && "
                f"!(seed_checked & 0x{1 << ordinal:x}u)) {{\n"
                f"                seed_checked |= 0x{1 << ordinal:x}u;\n"
                f"                if ({helper}(data, len, offset)) "
                f"return {match_value};\n"
                f"            }}")
        fast_helpers.append(f"""
static inline unsigned char {prefix}_ascii_lower(unsigned char value) {{
    return value >= 'A' && value <= 'Z' ? (unsigned char)(value | 0x20u) : value;
}}
static int {prefix}_fast_accept(
        const unsigned char *data, size_t len, size_t offset) {{
    uint32_t seed_checked = 0;
    for (size_t pos = offset; pos < len && seed_checked != 0x{all_hits:x}u; pos++) {{
        uint32_t seed_candidates = 0;
        switch (data[pos]) {{
{chr(10).join(case_code)}
        default:
            break;
        }}
{chr(10).join(dispatch)}
    }}
    return 0;
}}
""")
        fast_entry = (
            f"    if (len >= offset && len - offset <= "
            f"{fast_accept_scan_budget}u && "
            f"{prefix}_fast_accept(data, len, offset)) "
            f"return {match_value};\n")

    code = "\n".join(fast_helpers) + f"""
static const uint8_t {prefix}_class[256] = {{
{rows(nfa['byte_class'], 16, False)}
}};
static const uint8_t {prefix}_transition_id[{len(nfa['transition_ids'])}] = {{
{rows(nfa['transition_ids'], 16, False)}
}};
static const uint64_t {prefix}_vector[{len(flat_vectors)}] = {{
{rows(flat_vectors)}
}};
static const uint64_t {prefix}_accept[{len(flat_accepts)}] = {{
{rows(flat_accepts)}
}};
static const uint64_t {prefix}_source[{len(flat_sources)}] = {{
{rows(flat_sources)}
}};
static const uint64_t {prefix}_eof[{len(flat_eof)}] = {{
{rows(flat_eof)}
}};
static const uint64_t {prefix}_start[{nfa['word_count']}] = {{
{rows(nfa['start_mask'])}
}};

{linkage}int {fn_name}(const unsigned char *data, size_t len, size_t offset) {{
{fast_entry}
{mandatory_seed_entry}
    uint64_t active[{nfa['word_count']}];
    for (size_t word = 0; word < {nfa['word_count']}u; word++)
        active[word] = {prefix}_start[word];
    uint32_t previous_word = offset > 0 && ((data[offset-1] >= '0' && data[offset-1] <= '9') ||
        (data[offset-1] >= 'A' && data[offset-1] <= 'Z') ||
        (data[offset-1] >= 'a' && data[offset-1] <= 'z') || data[offset-1] == '_');
    uint32_t bol = offset == 0;
    for (size_t pos = offset; pos < len; pos++) {{
        unsigned char input_byte = data[pos];
        {lower_code}
        uint32_t symbol = {prefix}_class[input_byte] +
            {nfa['class_count']}u * (previous_word + 2u * bol);
        const uint64_t *accept = &{prefix}_accept[
            symbol * {nfa['word_count']}u];
        for (size_t word = 0; word < {nfa['word_count']}u; word++)
            if (active[word] & accept[word]) return {match_value};

        uint64_t seen[{seen_words}] = {{0}};
        const uint8_t *transition_id = &{prefix}_transition_id[
            symbol * {nfa['state_count']}u];
        const uint64_t *source = &{prefix}_source[
            symbol * {nfa['word_count']}u];
        for (size_t word = 0; word < {nfa['word_count']}u; word++) {{
            uint64_t current = active[word] & source[word];
            while (current) {{
                uint32_t bit = (uint32_t)__builtin_ctzll(current);
                current &= current - 1;
                uint32_t state = (uint32_t)(word * 64u + bit);
                if (state < {nfa['state_count']}u) {{
                    uint32_t vector_id = transition_id[state];
                    if (vector_id)
                        seen[vector_id >> 6] |= 1ULL << (vector_id & 63u);
                }}
            }}
        }}

        uint64_t next[{nfa['word_count']}] = {{0}};
        for (size_t seen_word = 0; seen_word < {seen_words}u; seen_word++) {{
            uint64_t current = seen[seen_word];
            while (current) {{
                uint32_t bit = (uint32_t)__builtin_ctzll(current);
                current &= current - 1;
                uint32_t vector_id = (uint32_t)(seen_word * 64u + bit);
                const uint64_t *vector = &{prefix}_vector[
                    vector_id * {nfa['word_count']}u];
                for (size_t word = 0; word < {nfa['word_count']}u; word++)
                    next[word] |= vector[word];
            }}
        }}
        uint64_t any = 0;
        for (size_t word = 0; word < {nfa['word_count']}u; word++) {{
            active[word] = next[word];
            any |= next[word];
        }}
        if (!any) return 0;
        unsigned char byte = input_byte;
        previous_word = (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') ||
                        (byte >= 'a' && byte <= 'z') || byte == '_';
        bol = 0;
    }}

    const uint64_t *eof = &{prefix}_eof[
        (previous_word + 2u * bol) * {nfa['word_count']}u];
    for (size_t word = 0; word < {nfa['word_count']}u; word++)
        if (active[word] & eof[word]) return {match_value};
    return 0;
}}
"""
    return code
