from soar_sdk.action_results import ActionOutput


class PopularThreatCategory(ActionOutput):
    value: str
    count: int


class PopularThreatClassification(ActionOutput):
    suggested_threat_label: str
    popular_threat_category: list[PopularThreatCategory]
    popular_threat_name: list[PopularThreatCategory]
