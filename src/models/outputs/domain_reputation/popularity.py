from soar_sdk.action_results import ActionOutput, OutputField
from typing import Optional


class PopularityRank(ActionOutput):
    rank: int
    timestamp: int = OutputField(cef_types=["timestamp"], example_values=[1613635210])


class PopularityRanks(ActionOutput):
    Majestic: Optional[PopularityRank]
    Statvoo: Optional[PopularityRank]
    Alexa: Optional[PopularityRank]
    Cisco_Umbrella: Optional[PopularityRank]
    Quantcast: Optional[PopularityRank]
    Cloudflare_Radar: Optional[PopularityRank]
