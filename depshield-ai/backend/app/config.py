from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://depshield:depshield@postgres:5432/depshield"
    redis_url: str = "redis://redis:6379/0"
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "depshield-pass"

    jwt_secret: str = "change-me-in-production"
    jwt_expire_minutes: int = 60 * 12

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    nvd_api_key: str = ""
    github_token: str = ""

    cors_origins: str = "http://localhost:5173,http://localhost:8080"
    ai_explain_top_n: int = 8


settings = Settings()
