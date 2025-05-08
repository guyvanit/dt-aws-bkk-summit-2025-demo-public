from datetime import datetime

from dataclasses import dataclass, field


@dataclass
class FlowNodeInfo:
    name: str
    start_at: datetime
    last_updated_at: datetime

    action_info: dict | None = None
    node_input: list[dict] = field(default_factory=list)
    node_output: list[dict] = field(default_factory=list)
