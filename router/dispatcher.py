"""
Task Dispatcher - handles agent invocation and execution.

Manages the coordination of task execution across different specialized agents.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

import structlog

logger = structlog.get_logger(__name__)


class AgentInterface(ABC):
    """
    Abstract base class for all agents in the framework.
    """

    @abstractmethod
    async def execute(self, task: "Task") -> Dict[str, Any]:
        """
        Execute a task.

        Args:
            task: Task to execute

        Returns:
            Dict containing task results
        """
        pass

    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the agent.
        """
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        """
        Shutdown the agent gracefully.
        """
        pass


class TaskDispatcher:
    """
    Dispatcher manages the routing of tasks to specific agents.
    
    Responsibilities:
    - Maintain registry of available agents
    - Dispatch tasks to appropriate agents
    - Handle agent availability and lifecycle
    - Manage concurrent execution
    """

    def __init__(self):
        """
        Initialize the task dispatcher.
        """
        self.agents: Dict[str, AgentInterface] = {}
        self.agent_status: Dict[str, str] = {}
        self.execution_history: list = []

    async def initialize(self) -> None:
        """
        Initialize all registered agents.
        """
        await logger.ainfo("Initializing TaskDispatcher...")
        for agent_name, agent in self.agents.items():
            try:
                await agent.initialize()
                self.agent_status[agent_name] = "ready"
                await logger.ainfo(f"Agent initialized: {agent_name}")
            except Exception as e:
                await logger.aerror(
                    f"Failed to initialize agent {agent_name}: {str(e)}"
                )
                self.agent_status[agent_name] = "failed"

    def register_agent(self, name: str, agent: AgentInterface) -> None:
        """
        Register an agent with the dispatcher.

        Args:
            name: Agent name/identifier
            agent: Agent instance
        """
        self.agents[name] = agent
        self.agent_status[name] = "registered"
        logging.info(f"Agent registered: {name}")

    async def dispatch(
        self,
        agent_name: str,
        task: "Task",
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """
        Dispatch a task to a specific agent.

        Args:
            agent_name: Name of the agent to dispatch to
            task: Task to execute
            timeout: Execution timeout in seconds

        Returns:
            Dict containing task results

        Raises:
            ValueError: If agent not found
            TimeoutError: If task execution times out
        """
        if agent_name not in self.agents:
            raise ValueError(f"Agent not found: {agent_name}")

        agent = self.agents[agent_name]
        status = self.agent_status.get(agent_name, "unknown")

        if status != "ready":
            await logger.awarning(
                f"Agent {agent_name} not in ready state: {status}"
            )

        try:
            await logger.ainfo(
                "dispatching_task",
                task_id=task.task_id,
                agent=agent_name,
            )

            # Execute with timeout
            results = await asyncio.wait_for(
                agent.execute(task),
                timeout=timeout,
            )

            # Record execution
            self.execution_history.append({
                "task_id": task.task_id,
                "agent": agent_name,
                "status": "success",
            })

            await logger.ainfo(
                "task_dispatched_successfully",
                task_id=task.task_id,
                agent=agent_name,
            )

            return results

        except asyncio.TimeoutError:
            await logger.aerror(
                "task_dispatch_timeout",
                task_id=task.task_id,
                agent=agent_name,
                timeout=timeout,
            )
            raise TimeoutError(
                f"Task {task.task_id} timed out after {timeout}s in agent {agent_name}"
            )
        except Exception as e:
            await logger.aerror(
                "task_dispatch_failed",
                task_id=task.task_id,
                agent=agent_name,
                error=str(e),
            )
            raise

    async def shutdown(self) -> None:
        """
        Shutdown all agents gracefully.
        """
        await logger.ainfo("Shutting down TaskDispatcher...")
        for agent_name, agent in self.agents.items():
            try:
                await agent.shutdown()
                await logger.ainfo(f"Agent shutdown: {agent_name}")
            except Exception as e:
                await logger.aerror(
                    f"Error shutting down agent {agent_name}: {str(e)}"
                )

    def get_agent_status(self) -> Dict[str, str]:
        """
        Get status of all agents.

        Returns:
            Dict mapping agent names to their status
        """
        return self.agent_status.copy()

    def get_execution_history(self, limit: int = 100) -> list:
        """
        Get execution history.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of execution records
        """
        return self.execution_history[-limit:]
