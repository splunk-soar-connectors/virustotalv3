from typing import Optional
from soar_sdk.action_results import ActionOutput, OutputField


class FileSandboxResult(ActionOutput):
    category: str = OutputField(example_values=["malicious", "harmless", "suspicious"])
    confidence: Optional[int]
    malware_classification: Optional[list[str]] = OutputField(example_values=["CLEAN"])
    malware_names: Optional[list[str]]
    sandbox_name: str


class FileSandboxVerdicts(ActionOutput):
    Zenbox: Optional[FileSandboxResult]
    Zenbox_Linux: Optional[FileSandboxResult]
