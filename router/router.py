"""
Main Agent Router - orchestrates task routing and agent coordination.

The router is the central nervous system of 0xFluxHunter, responsible for:
- Task classification and routing
- Agent coordination and orchestration
- Result aggregation and correlation
- Memory management across agents
- Error handling and retry logic
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field
import structlog

from router.dispatcher import TaskDispatcher
from router.memory import MemoryManager
from router.context_manager import ContextManager

logger = structlog.get_logger(__name__)


class TaskType(str, Enum):
    """Enumeration of supported task types."""
    RECON = "recon"
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    HOST_DETECTION = "host_detection"
    URL_COLLECTION = "url_collection"
    TECH_FINGERPRINT = "technology_fingerprinting"
    OAUTH_ANALYSIS = "oauth_analysis"
    JWT_ANALYSIS = "jwt_analysis"
    AUTH_TESTING = "authentication_testing"
    IDOR_ANALYSIS = "idor_analysis"
    SSRF_ANALYSIS = "ssrf_analysis"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    REPORT_GENERATION = "report_generation"


class TaskStatus(str, Enum):
    """Task execution status states."""
    PENDING = "pending"
    ROUTING = "routing"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"


class Task(BaseModel):
    """Represents a task to be routed and executed."""
    task_id: str
    task_type: TaskType
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 5  # 1-10, higher is more important
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3


class RoutingDecision(BaseModel):
    """Result of task routing classification."""
    task_id: str
    target_agent: str
    confidence: float
    reason: str
    agents_considered: List[str]


class AgentRouter:
    """
    Central router for coordinating agents and executing tasks.

    Responsibilities:
    - Classify incoming tasks
    - Route tasks to appropriate agents
    - Manage agent coordination
    - Aggregate and correlate findings
    - Handle retries and error recovery
    """

    def __init__(self, max_concurrent_tasks: int = 3):
        """
        Initialize the Agent Router.

        Args:
            max_concurrent_tasks: Maximum number of concurrent task executions
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.dispatcher = TaskDispatcher()
        self.memory = MemoryManager()
        self.context = ContextManager()
        self.active_tasks: Dict[str, Task] = {}
        self.completed_tasks: List[Task] = []
        self.task_queue: asyncio.Queue = asyncio.Queue()

    async def initialize(self) -> None:
        """
        Initialize router components and start background workers.
        Must be called before routing tasks.
        """
        await logger.ainfo("Initializing AgentRouter...")
        await self.memory.initialize()
        await self.dispatcher.initialize()
        await logger.ainfo("AgentRouter initialized successfully")

    async def route_task(self, task: Task) -> RoutingDecision:
        """
        Classify and route a task to the appropriate agent.

        Args:
            task: Task to be routed

        Returns:
            RoutingDecision: Routing classification and agent assignment
        """
        await logger.ainfo("routing_task", task_id=task.task_id, task_type=task.task_type)

        task.status = TaskStatus.ROUTING

        # Task classification logic
        routing_map = {
            TaskType.RECON: "recon_agent",
            TaskType.SUBDOMAIN_ENUM: "recon_agent",
            TaskType.HOST_DETECTION: "recon_agent",
            TaskType.URL_COLLECTION: "recon_agent",
            TaskType.TECH_FINGERPRINT: "analyzer_agent",
            TaskType.OAUTH_ANALYSIS: "oauth_agent",
            TaskType.JWT_ANALYSIS: "jwt_agent",
            TaskType.AUTH_TESTING: "auth_agent",
            TaskType.IDOR_ANALYSIS: "idor_agent",
            TaskType.SSRF_ANALYSIS: "ssrf_agent",
            TaskType.VULNERABILITY_ANALYSIS: "analyzer_agent",
            TaskType.REPORT_GENERATION: "report_agent",
        }

        target_agent = routing_map.get(task.task_type, "analyzer_agent")

        decision = RoutingDecision(
            task_id=task.task_id,
            target_agent=target_agent,
            confidence=0.95,
            reason=f"Task type {task.task_type} routed to {target_agent}",
            agents_considered=list(routing_map.values()),
        )

        # Store routing decision in memory
        await self.memory.store(
            f"routing:{task.task_id}",
            decision.model_dump(),
        )

        await logger.ainfo(
            "task_routed",
            task_id=task.task_id,
            target_agent=target_agent,
            confidence=decision.confidence,
        )

        return decision

    async def execute_task(self, task: Task) -> Task:
        """
        Execute a task through the appropriate agent.

        Args:
            task: Task to execute

        Returns:
            Task: Completed task with results
        """
        await logger.ainfo("executing_task", task_id=task.task_id)

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.utcnow()
        self.active_tasks[task.task_id] = task

        try:
            # Route task to appropriate agent
            routing_decision = await self.route_task(task)

            # Dispatch task execution
            results = await self.dispatcher.dispatch(
                routing_decision.target_agent,
                task,
            )

            task.results = results
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()

            await logger.ainfo(
                "task_completed",
                task_id=task.task_id,
                results_keys=list(results.keys()),
            )

        except Exception as e:
            await logger.aerror(
                "task_execution_failed",
                task_id=task.task_id,
                error=str(e),
            )

            task.errors.append(str(e))

            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.RETRY
                await logger.ainfo(
                    "task_retry",
                    task_id=task.task_id,
                    retry_count=task.retry_count,
                )
                # Retry after delay
                await asyncio.sleep(5)
                return await self.execute_task(task)
            else:
                task.status = TaskStatus.FAILED

        finally:
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]
            self.completed_tasks.append(task)

        return task

    async def execute_workflow(self, tasks: List[Task]) -> List[Task]:
        """
        Execute multiple tasks in a coordinated workflow.

        Args:
            tasks: List of tasks to execute

        Returns:
            List[Task]: Completed tasks with results
        """
        await logger.ainfo("starting_workflow", task_count=len(tasks))

        # Execute tasks with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent_tasks)

        async def execute_with_semaphore(task: Task) -> Task:
            async with semaphore:
                return await self.execute_task(task)

        completed_tasks = await asyncio.gather(
            *[execute_with_semaphore(task) for task in tasks],
            return_exceptions=False,
        )

        await logger.ainfo(
            "workflow_completed",
            total_tasks=len(tasks),
            completed=len([t for t in completed_tasks if t.status == TaskStatus.COMPLETED]),
            failed=len([t for t in completed_tasks if t.status == TaskStatus.FAILED]),
        )

        return completed_tasks

    async def correlate_findings(self, tasks: List[Task]) -> Dict[str, Any]:
        """
        Correlate findings across multiple tasks.

        Args:
            tasks: Completed tasks to correlate

        Returns:
            Dict containing correlated findings and insights
        """
        await logger.ainfo("correlating_findings", task_count=len(tasks))

        correlated = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tasks": len(tasks),
            "findings_by_type": {},
            "aggregated_findings": [],
            "insights": [],
        }

        # Correlate findings from each task
        for task in tasks:
            if task.status == TaskStatus.COMPLETED and task.results:
                task_type = task.task_type.value
                if task_type not in correlated["findings_by_type"]:
                    correlated["findings_by_type"][task_type] = []

                correlated["findings_by_type"][task_type].append(task.results)
                correlated["aggregated_findings"].extend(task.results.get("findings", []))

        # Store correlation in memory
        await self.memory.store(
            "correlations:latest",
            correlated,
        )

        await logger.ainfo(
            "findings_correlated",
            finding_count=len(correlated["aggregated_findings"]),
        )

        return correlated

    def get_task_status(self, task_id: str) -> Optional[Task]:
        """
        Get the current status of a task.

        Args:
            task_id: Task identifier

        Returns:
            Task: Current task state or None if not found
        """
        return self.active_tasks.get(task_id) or next(
            (t for t in self.completed_tasks if t.task_id == task_id),
            None,
        )

    async def get_scan_report(self, scan_id: str) -> Dict[str, Any]:
        """
        Retrieve a scan report by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            Dict containing scan report and findings
        """
        report = await self.memory.retrieve(f"report:{scan_id}")
        return report or {"error": "Report not found"}

    async def shutdown(self) -> None:
        """
        Gracefully shutdown the router and all components.
        """
        await logger.ainfo("Shutting down AgentRouter...")
        await self.memory.shutdown()
        await self.dispatcher.shutdown()
        await logger.ainfo("AgentRouter shutdown complete")
