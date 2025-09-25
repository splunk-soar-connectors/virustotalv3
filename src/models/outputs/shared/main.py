from soar_sdk.action_results import ActionOutput, OutputField


class APILinks(ActionOutput):
    self: str = OutputField(
        cef_types=["url"],
        example_values=["https://www.virustotal.com/api/v3/domains/test.com"],
    )


class TotalVotes(ActionOutput):
    harmless: int
    malicious: int
