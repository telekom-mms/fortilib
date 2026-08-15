from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    FORTIGATE_URL: str = ""
    FORTIGATE_VDOM: str = ""
    FORTIGATE_ACCESS_TOKEN: str = ""


settings = Settings()
