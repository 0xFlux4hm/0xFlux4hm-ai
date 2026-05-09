"""
Context Manager - maintains execution context and metadata.

Manages task context, execution state, and metadata across the framework.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


class ExecutionContext:
    """
    Represents the execution context for a task or workflow.
    """

    def __init__(self, context_id: str, target: str):
        """
        Initialize execution context.

        Args:
            context_id: Unique context identifier
            target: Target being scanned/analyzed
        """
        self.context_id = context_id
        self.target = target
        self.created_at = datetime.utcnow()
        self.metadata: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}
        self.errors: list = []
        self.agent_results: Dict[str, Any] = {}

    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to context.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value

    def add_agent_result(self, agent_name: str, result: Dict[str, Any]) -> None:
        """
        Add result from an agent.

        Args:
            agent_name: Name of the agent
            result: Agent result
        """
        self.agent_results[agent_name] = result

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary.

        Returns:
            Dictionary representation of context
        """
        return {
            "context_id": self.context_id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
            "results": self.results,
            "agent_results": self.agent_results,
            "errors": self.errors,
        }


class ContextManager:
    """
    Manages execution contexts for tasks and workflows.
    
    Responsibilities:
    - Create and manage execution contexts
    - Maintain context state
    - Provide context access to agents
    - Handle context lifecycle
    """

    def __init__(self):
        """
        Initialize context manager.
        """
        self.contexts: Dict[str, ExecutionContext] = {}
        self.active_contexts: set = set()

    async def create_context(
        self,
        context_id: str,
        target: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExecutionContext:
        """
        Create a new execution context.

        Args:
            context_id: Unique context identifier
            target: Target being scanned
            metadata: Initial metadata

        Returns:
            ExecutionContext: Created context
        """
        context = ExecutionContext(context_id, target)

        if metadata:
            for key, value in metadata.items():
                context.add_metadata(key, value)

        self.contexts[context_id] = context
        self.active_contexts.add(context_id)

        await logger.ainfo(
            "context_created",
            context_id=context_id,
            target=target,
        )

        return context

    async def get_context(self, context_id: str) -> Optional[ExecutionContext]:
        """
        Get an execution context.

        Args:
            context_id: Context identifier

        Returns:
            ExecutionContext or None if not found
        """
        return self.contexts.get(context_id)

    async def update_context(
        self,
        context_id: str,
        updates: Dict[str, Any],
    ) -> bool:
        """
        Update context metadata.

        Args:
            context_id: Context identifier
            updates: Updates to apply

        Returns:
            True if successful, False otherwise
        """
        context = self.contexts.get(context_id)
        if not context:
            return False

        for key, value in updates.items():
            context.add_metadata(key, value)

        return True

    async def close_context(self, context_id: str) -> Optional[ExecutionContext]:
        """
        Close and retrieve a context.

        Args:
            context_id: Context identifier

        Returns:
            Closed ExecutionContext or None if not found
        """
        context = self.contexts.get(context_id)
        if context:
            self.active_contexts.discard(context_id)
            await logger.ainfo(
                "context_closed",
                context_id=context_id,
            )
        return context

    def get_active_contexts(self) -> set:
        """
        Get all active context IDs.

        Returns:
            Set of active context IDs
        """
        return self.active_contexts.copy()
