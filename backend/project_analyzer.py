"""
CodeJev Project Analyzer - Phase 7
===================================

Builds project-level module/function indexes, resolves simple imports,
and provides cross-file function call resolution across multiple Python files.
"""

import ast
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


from backend.analysis.function_summary import SummaryCache


@dataclass
class FunctionDefinition:
    """
    Metadata representation of a indexed function definition in a project.
    """
    func_name: str
    module_name: str
    file: str
    node: ast.AST
    start_line: int
    end_line: int
    return_values: List[ast.AST]


class ProjectAnalyzer:
    """
    Indexes multiple Python files in a project and resolves cross-file imports & function calls.
    """
    def __init__(self, files: Dict[str, str]):
        self.files = files
        self.trees: Dict[str, ast.AST] = {}
        self.module_index: Dict[str, str] = {}  # module_name -> filename
        self.func_index: Dict[Tuple[str, str], FunctionDefinition] = {}  # (module_name, func_name) -> FunctionDefinition
        self.file_imports: Dict[str, Dict[str, Tuple[str, str]]] = {}  # filename -> {local_alias: (target_module, target_symbol)}
        self.summary_cache = SummaryCache(project_analyzer=self)

        self._parse_and_index_project()

    def _parse_and_index_project(self) -> None:
        """Parses all project files into ASTs and populates module/function indexes."""
        for filename, code in self.files.items():
            if not code or not code.strip():
                continue

            try:
                tree = ast.parse(code, filename=filename)
                self.trees[filename] = tree

                # Module name derived from filename (e.g. 'auth.py' -> 'auth', 'pkg/db.py' -> 'db')
                mod_name = self._filename_to_module(filename)
                self.module_index[mod_name] = filename
                self.file_imports[filename] = {}

                # Index function definitions and imports
                self._index_file_symbols(filename, mod_name, tree)
            except SyntaxError:
                # Broken syntax files are skipped from indexing cleanly
                continue

    def _index_file_symbols(self, filename: str, mod_name: str, tree: ast.AST) -> None:
        """Indexes function definitions and import statements within a single AST tree."""
        for node in ast.walk(tree):
            # Index function definitions
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                returns = self._extract_returns(node)
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)

                func_def = FunctionDefinition(
                    func_name=node.name,
                    module_name=mod_name,
                    file=filename,
                    node=node,
                    start_line=start_line,
                    end_line=end_line,
                    return_values=returns,
                )
                self.func_index[(mod_name, node.name)] = func_def

            # Index 'from module import func'
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    self.file_imports[filename][local_name] = (node.module, alias.name)

            # Index 'import module'
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    self.file_imports[filename][local_name] = (alias.name, "*")

    def _extract_returns(self, func_node: ast.AST) -> List[ast.AST]:
        """Extracts return expression nodes from a function body."""
        return_nodes = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return_nodes.append(node.value)
        return return_nodes

    def resolve_function(self, from_file: str, call_node: ast.Call) -> Optional[FunctionDefinition]:
        """
        Resolves a call node (e.g. authenticate(...) or auth.authenticate(...))
        to its cross-file FunctionDefinition if known in the project.
        """
        # Case A: Direct function call (e.g. authenticate(...))
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id

            # Check imports in from_file first
            imports = self.file_imports.get(from_file, {})
            if func_name in imports:
                target_mod, target_sym = imports[func_name]
                if target_sym != "*":
                    return self.func_index.get((target_mod, target_sym))

            # Check if function is defined in current file's module
            from_mod = self._filename_to_module(from_file)
            if (from_mod, func_name) in self.func_index:
                return self.func_index[(from_mod, func_name)]

        # Case B: Attribute call (e.g. auth.authenticate(...))
        elif isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Name):
            mod_alias = call_node.func.value.id
            method_name = call_node.func.attr

            # Check if mod_alias was imported
            imports = self.file_imports.get(from_file, {})
            if mod_alias in imports:
                target_mod, _ = imports[mod_alias]
                return self.func_index.get((target_mod, method_name))

            # Direct module match
            if mod_alias in self.module_index:
                return self.func_index.get((mod_alias, method_name))

        return None

    def resolve_call_returns(
        self, 
        from_file: str, 
        call_node: ast.Call, 
        visited: Optional[Set[Tuple[str, str]]] = None
    ) -> List[ast.AST]:
        """
        Resolves the return expression nodes for a function call across files.
        Uses visited set to prevent infinite recursion on cyclic calls.
        """
        if visited is None:
            visited = set()

        func_def = self.resolve_function(from_file, call_node)
        if not func_def:
            return []  # UNKNOWN function -> returns empty list (no speculative assumptions)

        call_key = (func_def.file, func_def.func_name)
        if call_key in visited:
            return []  # Cycle detected -> terminate recursion

        visited.add(call_key)
        return func_def.return_values

    def _filename_to_module(self, filename: str) -> str:
        """Converts a filename path to module name (e.g. 'pkg/auth.py' -> 'auth')."""
        base = os.path.basename(filename)
        if base.endswith(".py"):
            return base[:-3]
        return base
