"""
Memory Manager - persistent storage for shared agent memory and findings.

Manages correlation data, findings, and contextual information across agents.
"""

import json
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


class MemoryManager:
    """
    Manages shared memory and findings across agents.
    
    Features:
    - Key-value storage for agent memory
    - Finding correlation and deduplication
    - Persistent storage support
    - Memory lifecycle management
    """

    def __init__(self, max_items: int = 10000, persistence_file: str = "data/memory.json"):
        """
        Initialize memory manager.

        Args:
            max_items: Maximum number of items to store
            persistence_file: Path to persistence file
        """
        self.max_items = max_items
        self.persistence_file = persistence_file
        self.memory: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.correlations: Dict[str, List[str]] = {}

    async def initialize(self) -> None:
        """
        Initialize memory manager and load persisted data.
        """
        await logger.ainfo("Initializing MemoryManager...")
        try:
            await self._load_persistent_data()
            await logger.ainfo(
                "MemoryManager initialized",
                items_loaded=len(self.memory),
            )
        except Exception as e:
            await logger.awarning(f"Could not load persistent data: {str(e)}")

    async def store(self, key: str, value: Any) -> None:
        """
        Store a value in memory.

        Args:
            key: Storage key
            value: Value to store
        """
        if len(self.memory) >= self.max_items:
            # Remove oldest entries
            oldest_keys = sorted(
                self.memory.keys(),
                key=lambda k: self.memory[k].get("_timestamp", 0),
            )[:len(self.memory) // 10]
            for k in oldest_keys:
                del self.memory[k]

        self.memory[key] = {
            "value": value,
            "_timestamp": datetime.utcnow().isoformat(),
        }

        await logger.adebug(f"Stored in memory: {key}")

    async def retrieve(self, key: str) -> Optional[Any]:
        """
        Retrieve a value from memory.

        Args:
            key: Storage key

        Returns:
            Stored value or None if not found
        """
        if key in self.memory:
            return self.memory[key].get("value")
        return None

    async def store_finding(self, finding: Dict[str, Any]) -> None:
        """
        Store a security finding.

        Args:
            finding: Finding object with structure:
                - title: Finding title
                - severity: Severity level (critical, high, medium, low, info)
                - type: Finding type (vulnerability, config issue, etc.)
                - source: Agent that discovered the finding
                - data: Finding-specific data
        """
        finding_with_metadata = {
            **finding,
            "_timestamp": datetime.utcnow().isoformat(),
            "_id": len(self.findings),
        }

        # Check for duplicates
        if not await self._is_duplicate_finding(finding):
            self.findings.append(finding_with_metadata)
            await logger.ainfo(
                "finding_stored",
                title=finding.get("title"),
                severity=finding.get("severity"),
                source=finding.get("source"),
            )

    async def get_findings(
        self,
        severity: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve findings with optional filtering.

        Args:
            severity: Filter by severity level
            source: Filter by source agent

        Returns:
            List of findings matching criteria
        """
        findings = self.findings

        if severity:
            findings = [f for f in findings if f.get("severity") == severity]

        if source:
            findings = [f for f in findings if f.get("source") == source]

        return findings

    async def correlate_findings(
        self,
        finding1_id: int,
        finding2_id: int,
        relationship: str,
    ) -> None:
        """
        Create correlation between two findings.

        Args:
            finding1_id: First finding ID
            finding2_id: Second finding ID
            relationship: Type of relationship
        """
        key = f"{finding1_id}:{finding2_id}"
        if key not in self.correlations:
            self.correlations[key] = []
        self.correlations[key].append(relationship)

        await logger.adebug(f"Findings correlated: {key} ({relationship})")

    async def _is_duplicate_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Check if a finding is a duplicate.

        Args:
            finding: Finding to check

        Returns:
            True if duplicate found, False otherwise
        """
        finding_hash = hash(
            (finding.get("title"), finding.get("type"), finding.get("source"))
        )
        for existing in self.findings:
            existing_hash = hash(
                (
                    existing.get("title"),
                    existing.get("type"),
                    existing.get("source"),
                )
            )
            if finding_hash == existing_hash:
                return True
        return False

    async def _load_persistent_data(self) -> None:
        """
        Load memory from persistent storage.
        """
        try:
            with open(self.persistence_file, "r") as f:
                data = json.load(f)
                self.memory = data.get("memory", {})
                self.findings = data.get("findings", [])
                self.correlations = data.get("correlations", {})
        except FileNotFoundError:
            pass  # First run, no persisted data

    async def save_persistent_data(self) -> None:
        """
        Save memory to persistent storage.
        """
        try:
            data = {
                "memory": self.memory,
                "findings": self.findings,
                "correlations": self.correlations,
            }
            with open(self.persistence_file, "w") as f:
                json.dump(data, f, indent=2)
            await logger.ainfo("Memory persisted to storage")
        except Exception as e:
            await logger.aerror(f"Failed to persist memory: {str(e)}")

    async def shutdown(self) -> None:
        """
        Shutdown memory manager and save data.
        """
        await logger.ainfo("Shutting down MemoryManager...")
        await self.save_persistent_data()
        await logger.ainfo("MemoryManager shutdown complete")
