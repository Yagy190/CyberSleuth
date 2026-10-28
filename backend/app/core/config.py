"""
CyberSleuth AI – Application Configuration
Member 2: Backend & Data Engineering
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "CyberSleuth AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # ── Database ───────────────────────────────────────────────────────────────
    DB_URL: str = "postgresql+psycopg2://cyber:secret@localhost:5432/cyber_sleuth"

    # ── JWT Auth ───────────────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_32+_CHARS"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── LLM / RAG ─────────────────────────────────────────────────────────────
    GEMINI_API_KEY: str = ""
    MOCK_LLM: bool = True          # set False to use real Gemini
    EMBED_MODEL: str = "all-MiniLM-L6-v2"
    RAG_TOP_K: int = 5

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT: str = "60/minute"

    # ── Paths ─────────────────────────────────────────────────────────────────
    DATASETS_DIR: str = "../CyberSleuth_Synthetic_Dataset/datasets"
    MODELS_DIR: str = "./models"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
