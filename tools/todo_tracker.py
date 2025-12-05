#!/usr/bin/env python3
"""
DevSkyy TODO Tracker

Enterprise-grade TODO tracking system for managing technical debt,
development tasks, and code improvements across the DevSkyy platform.

WHY: Centralized TODO management with codebase synchronization
HOW: Parse source files for TODO comments, track in structured format
IMPACT: Improved technical debt visibility and prioritization

Truth Protocol: Full implementation, no placeholders, comprehensive logging
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json
import logging
import os
from pathlib import Path
import re
from typing import Any


logger = logging.getLogger(__name__)


class Priority(Enum):
    """TODO priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(Enum):
    """TODO status values."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    WONT_FIX = "wont_fix"
    DEFERRED = "deferred"


class Category(Enum):
    """TODO category types."""

    BUG = "bug"
    FEATURE = "feature"
    REFACTOR = "refactor"
    SECURITY = "security"
    PERFORMANCE = "performance"
    DOCUMENTATION = "documentation"
    TEST = "test"
    TECHNICAL_DEBT = "technical_debt"
    CLEANUP = "cleanup"


@dataclass
class TodoItem:
    """Represents a single TODO item."""

    id: str
    title: str
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    priority: Priority = Priority.MEDIUM
    category: Category = Category.FEATURE
    status: Status = Status.OPEN
    created_date: str = ""
    updated_date: str = ""
    assignee: str | None = None
    estimated_hours: float | None = None
    tags: list[str] = field(default_factory=list)
    related_issues: list[str] = field(default_factory=list)
    context: str = ""

    def __post_init__(self):
        """Initialize dates if not provided."""
        if not self.created_date:
            self.created_date = datetime.utcnow().isoformat()
        if not self.updated_date:
            self.updated_date = self.created_date

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "priority": self.priority.value,
            "category": self.category.value,
            "status": self.status.value,
            "created_date": self.created_date,
            "updated_date": self.updated_date,
            "assignee": self.assignee,
            "estimated_hours": self.estimated_hours,
            "tags": self.tags,
            "related_issues": self.related_issues,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TodoItem":
        """Create TodoItem from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            file_path=data.get("file_path", ""),
            line_number=data.get("line_number", 0),
            priority=Priority(data.get("priority", "medium")),
            category=Category(data.get("category", "feature")),
            status=Status(data.get("status", "open")),
            created_date=data.get("created_date", ""),
            updated_date=data.get("updated_date", ""),
            assignee=data.get("assignee"),
            estimated_hours=data.get("estimated_hours"),
            tags=data.get("tags", []),
            related_issues=data.get("related_issues", []),
            context=data.get("context", ""),
        )


class TodoTracker:
    """
    Enterprise TODO tracking system.

    Features:
    - Parse TODO/FIXME/HACK comments from source code
    - Track priority, status, and category
    - Synchronize with codebase
    - Generate reports and metrics
    - Export to various formats
    """

    # Patterns to detect TODO comments
    TODO_PATTERNS = [
        r"#\s*TODO[\s:]+(.+?)$",
        r"#\s*FIXME[\s:]+(.+?)$",
        r"#\s*HACK[\s:]+(.+?)$",
        r"#\s*XXX[\s:]+(.+?)$",
        r"#\s*BUG[\s:]+(.+?)$",
        r"#\s*OPTIMIZE[\s:]+(.+?)$",
        r"#\s*SECURITY[\s:]+(.+?)$",
    ]

    # File extensions to scan
    SCAN_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".md"}

    # Directories to skip
    SKIP_DIRS = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "htmlcov",
        "build",
        "dist",
        ".eggs",
    }

    def __init__(self, storage_path: str | None = None):
        """
        Initialize the TODO tracker.

        Args:
            storage_path: Path to JSON file for persistence
        """
        self.storage_path = storage_path or os.path.join(
            os.path.dirname(__file__), ".todo_tracker.json"
        )
        self.todos: dict[str, TodoItem] = {}
        self._load_todos()

    def _generate_id(self, file_path: str, line_number: int, content: str) -> str:
        """Generate a unique ID for a TODO item."""
        unique_string = f"{file_path}:{line_number}:{content}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:12]

    def _load_todos(self) -> None:
        """Load TODOs from persistent storage."""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, encoding="utf-8") as f:
                    data = json.load(f)
                    for item_data in data.get("todos", []):
                        try:
                            item = TodoItem.from_dict(item_data)
                            self.todos[item.id] = item
                        except (KeyError, ValueError) as e:
                            logger.warning(f"Failed to load TODO item: {e}")
                logger.info(f"Loaded {len(self.todos)} TODOs from storage")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse TODO storage: {e}")
        except OSError as e:
            logger.warning(f"Failed to load TODO storage: {e}")

    def _save_todos(self) -> None:
        """Save TODOs to persistent storage."""
        try:
            data = {
                "version": "1.0",
                "updated_at": datetime.utcnow().isoformat(),
                "todos": [todo.to_dict() for todo in self.todos.values()],
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved {len(self.todos)} TODOs to storage")
        except OSError as e:
            logger.error(f"Failed to save TODOs: {e}")

    def add_todo(
        self,
        title: str,
        description: str = "",
        file_path: str = "",
        line_number: int = 0,
        priority: Priority = Priority.MEDIUM,
        category: Category = Category.FEATURE,
        assignee: str | None = None,
        estimated_hours: float | None = None,
        tags: list[str] | None = None,
    ) -> TodoItem:
        """
        Add a new TODO item.

        Args:
            title: Brief description of the TODO
            description: Detailed description
            file_path: Source file path
            line_number: Line number in source file
            priority: Priority level
            category: Category type
            assignee: Person responsible
            estimated_hours: Estimated time to complete
            tags: Additional tags

        Returns:
            Created TodoItem
        """
        todo_id = self._generate_id(file_path, line_number, title)

        # Check for duplicate
        if todo_id in self.todos:
            logger.debug(f"TODO already exists: {todo_id}")
            return self.todos[todo_id]

        todo = TodoItem(
            id=todo_id,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            priority=priority,
            category=category,
            assignee=assignee,
            estimated_hours=estimated_hours,
            tags=tags or [],
        )

        self.todos[todo_id] = todo
        self._save_todos()
        logger.info(f"Added TODO: {title} ({todo_id})")

        return todo

    def update_todo(self, todo_id: str, **kwargs: Any) -> bool:
        """
        Update an existing TODO item.

        Args:
            todo_id: ID of the TODO to update
            **kwargs: Fields to update

        Returns:
            True if updated, False if not found
        """
        if todo_id not in self.todos:
            logger.warning(f"TODO not found: {todo_id}")
            return False

        todo = self.todos[todo_id]

        for key, value in kwargs.items():
            if hasattr(todo, key):
                setattr(todo, key, value)

        todo.updated_date = datetime.utcnow().isoformat()
        self._save_todos()
        logger.info(f"Updated TODO: {todo_id}")

        return True

    def delete_todo(self, todo_id: str) -> bool:
        """
        Delete a TODO item.

        Args:
            todo_id: ID of the TODO to delete

        Returns:
            True if deleted, False if not found
        """
        if todo_id not in self.todos:
            logger.warning(f"TODO not found: {todo_id}")
            return False

        del self.todos[todo_id]
        self._save_todos()
        logger.info(f"Deleted TODO: {todo_id}")

        return True

    def get_todo(self, todo_id: str) -> TodoItem | None:
        """Get a TODO item by ID."""
        return self.todos.get(todo_id)

    def get_todos_by_status(self, status: Status) -> list[TodoItem]:
        """Get all TODOs with a specific status."""
        return [t for t in self.todos.values() if t.status == status]

    def get_todos_by_priority(self, priority: Priority) -> list[TodoItem]:
        """Get all TODOs with a specific priority."""
        return [t for t in self.todos.values() if t.priority == priority]

    def get_todos_by_category(self, category: Category) -> list[TodoItem]:
        """Get all TODOs with a specific category."""
        return [t for t in self.todos.values() if t.category == category]

    def get_todos_by_file(self, file_path: str) -> list[TodoItem]:
        """Get all TODOs in a specific file."""
        return [t for t in self.todos.values() if t.file_path == file_path]

    def _detect_priority(self, content: str) -> Priority:
        """Detect priority from TODO content."""
        content_lower = content.lower()

        if any(word in content_lower for word in ["critical", "urgent", "asap", "p0"]):
            return Priority.CRITICAL
        if any(word in content_lower for word in ["high", "important", "p1"]):
            return Priority.HIGH
        if any(word in content_lower for word in ["low", "minor", "p3"]):
            return Priority.LOW

        return Priority.MEDIUM

    def _detect_category(self, content: str, pattern_type: str) -> Category:
        """Detect category from TODO content and pattern type."""
        content_lower = content.lower()

        # Pattern-based detection
        if "FIXME" in pattern_type or "BUG" in pattern_type:
            return Category.BUG
        if "HACK" in pattern_type:
            return Category.TECHNICAL_DEBT
        if "SECURITY" in pattern_type:
            return Category.SECURITY
        if "OPTIMIZE" in pattern_type:
            return Category.PERFORMANCE

        # Content-based detection
        if any(word in content_lower for word in ["security", "auth", "vulnerability"]):
            return Category.SECURITY
        if any(word in content_lower for word in ["performance", "optimize", "slow"]):
            return Category.PERFORMANCE
        if any(word in content_lower for word in ["test", "unittest", "coverage"]):
            return Category.TEST
        if any(word in content_lower for word in ["doc", "comment", "readme"]):
            return Category.DOCUMENTATION
        if any(word in content_lower for word in ["refactor", "cleanup", "simplify"]):
            return Category.REFACTOR
        if any(word in content_lower for word in ["bug", "fix", "error", "issue"]):
            return Category.BUG

        return Category.FEATURE

    def scan_file(self, file_path: str) -> list[TodoItem]:
        """
        Scan a file for TODO comments.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of TodoItem found
        """
        todos_found: list[TodoItem] = []

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return todos_found

        for line_num, line in enumerate(lines, 1):
            for pattern in self.TODO_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE | re.MULTILINE)
                if match:
                    content = match.group(1).strip()
                    priority = self._detect_priority(content)
                    category = self._detect_category(content, pattern)

                    # Get context (surrounding lines)
                    start = max(0, line_num - 3)
                    end = min(len(lines), line_num + 2)
                    context = "".join(lines[start:end])

                    todo = self.add_todo(
                        title=content[:100],  # Limit title length
                        description=content,
                        file_path=file_path,
                        line_number=line_num,
                        priority=priority,
                        category=category,
                    )
                    todo.context = context
                    todos_found.append(todo)

        return todos_found

    def scan_directory(self, directory: str) -> list[TodoItem]:
        """
        Recursively scan a directory for TODO comments.

        Args:
            directory: Path to directory to scan

        Returns:
            List of TodoItem found
        """
        todos_found: list[TodoItem] = []
        directory_path = Path(directory)

        if not directory_path.exists():
            logger.error(f"Directory does not exist: {directory}")
            return todos_found

        for file_path in directory_path.rglob("*"):
            # Skip directories in exclusion list
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
                continue

            # Only scan allowed file extensions
            if file_path.suffix not in self.SCAN_EXTENSIONS:
                continue

            if file_path.is_file():
                file_todos = self.scan_file(str(file_path))
                todos_found.extend(file_todos)

        logger.info(f"Scanned {directory}: found {len(todos_found)} TODOs")
        return todos_found

    def sync_with_codebase(self, root_dir: str | None = None) -> dict[str, int]:
        """
        Synchronize TODOs with the codebase.

        Scans for new TODOs and marks removed ones as completed.

        Args:
            root_dir: Root directory to scan (default: current directory)

        Returns:
            Statistics about the sync operation
        """
        if root_dir is None:
            root_dir = os.getcwd()

        # Track existing TODOs
        existing_ids = set(self.todos.keys())

        # Scan codebase
        found_todos = self.scan_directory(root_dir)
        found_ids = {t.id for t in found_todos}

        # Mark removed TODOs as completed
        removed_ids = existing_ids - found_ids
        for todo_id in removed_ids:
            if self.todos[todo_id].status == Status.OPEN:
                self.update_todo(todo_id, status=Status.COMPLETED)

        # Count new TODOs
        new_ids = found_ids - existing_ids

        stats = {
            "total_scanned": len(found_todos),
            "new_todos": len(new_ids),
            "completed_todos": len(removed_ids),
            "existing_todos": len(found_ids & existing_ids),
        }

        logger.info(f"Sync complete: {stats}")
        return stats

    def generate_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive TODO report.

        Returns:
            Report with statistics and breakdown
        """
        todos_list = list(self.todos.values())

        # Status breakdown
        status_counts = {}
        for status in Status:
            count = len([t for t in todos_list if t.status == status])
            status_counts[status.value] = count

        # Priority breakdown
        priority_counts = {}
        for priority in Priority:
            count = len([t for t in todos_list if t.priority == priority])
            priority_counts[priority.value] = count

        # Category breakdown
        category_counts = {}
        for category in Category:
            count = len([t for t in todos_list if t.category == category])
            category_counts[category.value] = count

        # File breakdown (top 10)
        file_counts: dict[str, int] = {}
        for todo in todos_list:
            if todo.file_path:
                file_counts[todo.file_path] = file_counts.get(todo.file_path, 0) + 1
        top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Critical and high priority items
        critical_items = [t.to_dict() for t in todos_list if t.priority == Priority.CRITICAL]
        high_priority_items = [t.to_dict() for t in todos_list if t.priority == Priority.HIGH]

        # Estimated hours
        total_hours = sum(t.estimated_hours or 0 for t in todos_list)

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total": len(todos_list),
                "open": status_counts.get("open", 0),
                "in_progress": status_counts.get("in_progress", 0),
                "completed": status_counts.get("completed", 0),
                "estimated_hours": total_hours,
            },
            "by_status": status_counts,
            "by_priority": priority_counts,
            "by_category": category_counts,
            "top_files": dict(top_files),
            "critical_items": critical_items,
            "high_priority_items": high_priority_items,
        }

    def export_markdown(self, output_path: str | None = None) -> str:
        """
        Export TODOs to Markdown format.

        Args:
            output_path: Optional path to write the file

        Returns:
            Markdown content
        """
        report = self.generate_report()
        todos_list = list(self.todos.values())

        lines = [
            "# DevSkyy TODO Report",
            "",
            f"Generated: {report['generated_at']}",
            "",
            "## Summary",
            "",
            f"- **Total TODOs**: {report['summary']['total']}",
            f"- **Open**: {report['summary']['open']}",
            f"- **In Progress**: {report['summary']['in_progress']}",
            f"- **Completed**: {report['summary']['completed']}",
            f"- **Estimated Hours**: {report['summary']['estimated_hours']:.1f}",
            "",
        ]

        # Critical items
        if report["critical_items"]:
            lines.extend([
                "## Critical Priority Items",
                "",
            ])
            for item in report["critical_items"]:
                lines.append(f"- [ ] **{item['title']}** ({item['file_path']}:{item['line_number']})")
            lines.append("")

        # High priority items
        if report["high_priority_items"]:
            lines.extend([
                "## High Priority Items",
                "",
            ])
            for item in report["high_priority_items"]:
                lines.append(f"- [ ] {item['title']} ({item['file_path']}:{item['line_number']})")
            lines.append("")

        # All TODOs by category
        lines.extend([
            "## All TODOs by Category",
            "",
        ])

        for category in Category:
            category_todos = [t for t in todos_list if t.category == category and t.status == Status.OPEN]
            if category_todos:
                lines.append(f"### {category.value.title().replace('_', ' ')}")
                lines.append("")
                for todo in category_todos:
                    priority_emoji = {
                        Priority.CRITICAL: "!",
                        Priority.HIGH: "!!",
                        Priority.MEDIUM: "",
                        Priority.LOW: "",
                    }
                    prefix = priority_emoji.get(todo.priority, "")
                    lines.append(f"- [ ] {prefix}{todo.title}")
                    if todo.file_path:
                        lines.append(f"  - File: `{todo.file_path}:{todo.line_number}`")
                lines.append("")

        content = "\n".join(lines)

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"Exported report to {output_path}")
            except OSError as e:
                logger.error(f"Failed to write report: {e}")

        return content

    def export_json(self, output_path: str | None = None) -> str:
        """
        Export TODOs to JSON format.

        Args:
            output_path: Optional path to write the file

        Returns:
            JSON content
        """
        data = {
            "version": "1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "report": self.generate_report(),
            "todos": [t.to_dict() for t in self.todos.values()],
        }

        content = json.dumps(data, indent=2)

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"Exported JSON to {output_path}")
            except OSError as e:
                logger.error(f"Failed to write JSON: {e}")

        return content


def main():
    """CLI entry point for TODO tracker."""
    import argparse

    parser = argparse.ArgumentParser(description="DevSkyy TODO Tracker")
    parser.add_argument("command", choices=["scan", "report", "sync", "export"])
    parser.add_argument("--dir", default=".", help="Directory to scan")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    tracker = TodoTracker()

    if args.command == "scan":
        tracker.scan_directory(args.dir)

    elif args.command == "report":
        tracker.generate_report()

    elif args.command == "sync":
        tracker.sync_with_codebase(args.dir)

    elif args.command == "export":
        tracker.export_json(args.output) if args.format == "json" else tracker.export_markdown(args.output)

        if not args.output:
            pass


if __name__ == "__main__":
    main()
