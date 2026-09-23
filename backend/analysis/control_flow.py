"""
CodeJev Control Flow Graph (CFG) - Phase 13
===========================================

Constructs a Control Flow Graph from Python AST trees.
Models entry, statements, conditions, branch splits, merge points, loop headers,
control jumps (return, raise, break, continue), try/except/finally, and exit nodes.
Preserves exact source line ranges on every node.
"""

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class CFGNode:
    """
    Represents a single node in a Control Flow Graph.
    """
    node_id: int
    file: str
    start_line: int
    end_line: int
    node_type: str  # "entry", "statement", "condition", "merge", "exit"
    ast_node: Optional[ast.AST] = None
    predecessors: List["CFGNode"] = field(default_factory=list)
    successors: List["CFGNode"] = field(default_factory=list)

    def add_successor(self, target: "CFGNode") -> None:
        """Adds a directed edge from self to target node."""
        if target not in self.successors:
            self.successors.append(target)
        if self not in target.predecessors:
            target.predecessors.append(self)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __repr__(self) -> str:
        return f"CFGNode({self.node_id}, type={self.node_type}, lines={self.start_line}-{self.end_line})"


class ControlFlowGraph:
    """
    Control Flow Graph representation for a function body or module AST.
    """
    def __init__(self, file: str, tree: ast.AST):
        self.file = file
        self.tree = tree
        self._next_id = 0
        self.nodes: Dict[int, CFGNode] = {}
        
        self.entry_node = self._create_node("entry", 1, 1)
        self.exit_node = self._create_node("exit", getattr(tree, "end_lineno", 1), getattr(tree, "end_lineno", 1))

        # Stack for loop break / continue target resolution
        self._loop_stack: List[Tuple[List[CFGNode], CFGNode]] = []  # (break_nodes, continue_target_node)

        self.build()

    def _create_node(self, node_type: str, start_line: int, end_line: int, ast_node: Optional[ast.AST] = None) -> CFGNode:
        self._next_id += 1
        node = CFGNode(
            node_id=self._next_id,
            file=self.file,
            start_line=start_line,
            end_line=end_line,
            node_type=node_type,
            ast_node=ast_node
        )
        self.nodes[node.node_id] = node
        return node

    def build(self) -> None:
        """Builds the CFG from the AST body."""
        body = []
        if isinstance(self.tree, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            body = self.tree.body
        elif isinstance(self.tree, list):
            body = self.tree
        else:
            body = [self.tree]

        exits = self._process_statement_list(body, [self.entry_node])
        for exit_n in exits:
            exit_n.add_successor(self.exit_node)

    def _process_statement_list(self, stmts: List[ast.AST], current_nodes: List[CFGNode]) -> List[CFGNode]:
        """Processes a sequence of statements and returns active exit nodes."""
        for stmt in stmts:
            if not current_nodes:
                break
            current_nodes = self._process_statement(stmt, current_nodes)
        return current_nodes

    def _process_statement(self, stmt: ast.AST, current_nodes: List[CFGNode]) -> List[CFGNode]:
        start = getattr(stmt, "lineno", 1)
        end = getattr(stmt, "end_lineno", start)

        # 1. Branching: If statement
        if isinstance(stmt, ast.If):
            cond_node = self._create_node("condition", start, start, stmt.test)
            for c in current_nodes:
                c.add_successor(cond_node)

            then_exits = self._process_statement_list(stmt.body, [cond_node])
            else_exits = self._process_statement_list(stmt.orelse, [cond_node]) if stmt.orelse else [cond_node]

            merge_node = self._create_node("merge", end, end)
            all_exits = then_exits + else_exits
            for e in all_exits:
                e.add_successor(merge_node)

            return [merge_node]

        # 2. Loops: While statement
        elif isinstance(stmt, ast.While):
            header_node = self._create_node("condition", start, start, stmt.test)
            for c in current_nodes:
                c.add_successor(header_node)

            break_nodes: List[CFGNode] = []
            self._loop_stack.append((break_nodes, header_node))

            body_exits = self._process_statement_list(stmt.body, [header_node])
            for b_exit in body_exits:
                b_exit.add_successor(header_node)

            self._loop_stack.pop()

            else_exits = self._process_statement_list(stmt.orelse, [header_node]) if stmt.orelse else [header_node]

            merge_node = self._create_node("merge", end, end)
            for e in else_exits + break_nodes:
                e.add_successor(merge_node)

            return [merge_node]

        # 3. Loops: For statement
        elif isinstance(stmt, ast.For):
            header_node = self._create_node("condition", start, start, stmt)
            for c in current_nodes:
                c.add_successor(header_node)

            break_nodes: List[CFGNode] = []
            self._loop_stack.append((break_nodes, header_node))

            body_exits = self._process_statement_list(stmt.body, [header_node])
            for b_exit in body_exits:
                b_exit.add_successor(header_node)

            self._loop_stack.pop()

            else_exits = self._process_statement_list(stmt.orelse, [header_node]) if stmt.orelse else [header_node]

            merge_node = self._create_node("merge", end, end)
            for e in else_exits + break_nodes:
                e.add_successor(merge_node)

            return [merge_node]

        # 4. Control Jumps: Return
        elif isinstance(stmt, ast.Return):
            ret_node = self._create_node("statement", start, end, stmt)
            for c in current_nodes:
                c.add_successor(ret_node)
            ret_node.add_successor(self.exit_node)
            return []  # Terminates local control flow path

        # 5. Control Jumps: Raise
        elif isinstance(stmt, ast.Raise):
            raise_node = self._create_node("statement", start, end, stmt)
            for c in current_nodes:
                c.add_successor(raise_node)
            raise_node.add_successor(self.exit_node)
            return []  # Terminates local control flow path

        # 6. Control Jumps: Break
        elif isinstance(stmt, ast.Break):
            break_node = self._create_node("statement", start, end, stmt)
            for c in current_nodes:
                c.add_successor(break_node)
            if self._loop_stack:
                self._loop_stack[-1][0].append(break_node)
            return []  # Jumps to loop merge

        # 7. Control Jumps: Continue
        elif isinstance(stmt, ast.Continue):
            cont_node = self._create_node("statement", start, end, stmt)
            for c in current_nodes:
                c.add_successor(cont_node)
            if self._loop_stack:
                cont_target = self._loop_stack[-1][1]
                cont_node.add_successor(cont_target)
            return []  # Jumps back to loop header

        # 8. Try / Except / Finally
        elif isinstance(stmt, ast.Try):
            try_node = self._create_node("statement", start, start, stmt)
            for c in current_nodes:
                c.add_successor(try_node)

            try_exits = self._process_statement_list(stmt.body, [try_node])

            handler_exits = []
            for handler in stmt.handlers:
                h_start = getattr(handler, "lineno", start)
                h_end = getattr(handler, "end_lineno", h_start)
                h_node = self._create_node("condition", h_start, h_end, handler)
                try_node.add_successor(h_node)
                h_exits = self._process_statement_list(handler.body, [h_node])
                handler_exits.extend(h_exits)

            all_branch_exits = try_exits + handler_exits
            if stmt.orelse:
                all_branch_exits = self._process_statement_list(stmt.orelse, all_branch_exits)

            if stmt.finalbody:
                all_branch_exits = self._process_statement_list(stmt.finalbody, all_branch_exits)

            merge_node = self._create_node("merge", end, end)
            for e in all_branch_exits:
                e.add_successor(merge_node)

            return [merge_node]

        # 9. Generic Statement (Assign, Expr, Call, etc.)
        else:
            stmt_node = self._create_node("statement", start, end, stmt)
            for c in current_nodes:
                c.add_successor(stmt_node)
            return [stmt_node]

    def get_reachable_nodes(self) -> Set[CFGNode]:
        """Returns set of all CFG nodes reachable from the entry node."""
        visited: Set[CFGNode] = set()
        queue = [self.entry_node]

        while queue:
            node = queue.pop(0)
            if node not in visited:
                visited.add(node)
                for succ in node.successors:
                    if succ not in visited:
                        queue.append(succ)

        return visited
