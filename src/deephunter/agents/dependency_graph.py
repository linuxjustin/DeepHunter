"""Dependency graph for agent execution ordering.

Supports topological sort to discover parallelizable groups
and detect cycles.
"""

from __future__ import annotations


class DependencyGraph:
    """Directed graph of agent dependencies.

    An edge ``A -> B`` means "B depends on A" (A must run before B).
    """

    def __init__(self) -> None:
        self._graph: dict[str, set[str]] = {}  # node -> set of dependencies
        self._dependents: dict[str, set[str]] = {}  # node -> set of dependents

    def add_node(self, name: str) -> None:
        if name not in self._graph:
            self._graph[name] = set()
        if name not in self._dependents:
            self._dependents[name] = set()

    def add_dependency(self, agent: str, depends_on: str) -> None:
        self.add_node(agent)
        self.add_node(depends_on)
        self._graph[agent].add(depends_on)
        self._dependents[depends_on].add(agent)

    def add_dependencies(self, agent: str, depends_on: list[str]) -> None:
        for dep in depends_on:
            self.add_dependency(agent, dep)

    def remove_node(self, name: str) -> None:
        self._graph.pop(name, None)
        self._dependents.pop(name, None)
        for deps in self._graph.values():
            deps.discard(name)
        for deps in self._dependents.values():
            deps.discard(name)

    def get_dependencies(self, name: str) -> list[str]:
        return list(self._graph.get(name, set()))

    def get_dependents(self, name: str) -> list[str]:
        return list(self._dependents.get(name, set()))

    def has_node(self, name: str) -> bool:
        return name in self._graph

    @property
    def nodes(self) -> list[str]:
        return list(self._graph.keys())

    @property
    def edge_count(self) -> int:
        return sum(len(deps) for deps in self._graph.values())

    def has_cycle(self) -> bool:
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def _dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for dep in self._graph.get(node, set()):
                if dep not in visited:
                    if _dfs(dep):
                        return True
                elif dep in rec_stack:
                    return True
            rec_stack.discard(node)
            return False

        for node in self._graph:
            if node not in visited:
                if _dfs(node):
                    return True
        return False

    def execution_order(self, agents: list[str] | None = None) -> list[list[str]]:
        """Topological sort returning levels of parallelizable groups.

        Each inner list contains agents that can run in parallel.
        Agents in level N depend on at least one agent in level N-1.
        """
        if agents is None:
            agents = self.nodes

        in_degree: dict[str, int] = {}
        for agent in agents:
            in_degree[agent] = 0

        for agent in agents:
            for dep in self._graph.get(agent, set()):
                if dep in agents:
                    in_degree[agent] = in_degree.get(agent, 0) + 1

        queue = [a for a in agents if in_degree.get(a, 0) == 0]
        levels: list[list[str]] = []

        while queue:
            levels.append(list(queue))
            next_queue: list[str] = []
            for current in queue:
                for dependent in self._dependents.get(current, set()):
                    if dependent in agents:
                        in_degree[dependent] = in_degree.get(dependent, 0) - 1
                        if in_degree[dependent] == 0:
                            next_queue.append(dependent)
            queue = next_queue

        return levels

    def clear(self) -> None:
        self._graph.clear()
        self._dependents.clear()
