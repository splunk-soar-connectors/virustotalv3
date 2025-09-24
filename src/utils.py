def sanitize_key_names(data: dict) -> dict:
    """Sanitize dictionary keys to only contain alphanumeric characters and underscores.

    If a sanitized key contains multiple underscores in a row, collapse them into a single underscore.
    If a value is a dictionary, recursively sanitize its keys.
    """
    sanitized_data = {}
    for key, value in data.items():
        sanitized_key = "".join(char if char.isalnum() else "_" for char in key)
        while "__" in sanitized_key:
            sanitized_key = sanitized_key.replace("__", "_")

        while sanitized_key.startswith("_"):
            sanitized_key = sanitized_key[1:]
        while sanitized_key.endswith("_"):
            sanitized_key = sanitized_key[:-1]

        sanitized_value = value
        if isinstance(value, dict):
            sanitized_value = sanitize_key_names(value)

        sanitized_data[sanitized_key] = sanitized_value
    return sanitized_data
