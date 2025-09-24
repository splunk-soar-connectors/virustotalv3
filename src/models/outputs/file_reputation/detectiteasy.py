from soar_sdk.action_results import ActionOutput


class DetectItEasyValue(ActionOutput):
    info: str
    name: str
    type: str
    version: str


class DetectItEasyResult(ActionOutput):
    filetype: str
    values: list[DetectItEasyValue]
