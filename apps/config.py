import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class Settings:
    """Application settings with environment variable validation and exception handling."""

    def __init__(self):
        try:
            self.DB_USER: str = os.getenv("DB_USER", "root")
            self.DB_PASSWORD: str = os.getenv("DB_PASSWORD", "Sujitmaity@143")
            self.DB_HOST: str = os.getenv("DB_HOST", "localhost")
            self.DB_PORT: int = int(os.getenv("DB_PORT", 3306))
            self.DB_NAME: str = os.getenv("DB_NAME", "genaicorelab")

            self.SECRET_KEY: str = os.getenv("SECRET_KEY", "your_secret_key")
            self.ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
            self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

            # Validate required environment variables
            self.validate_env_vars()
        except ValueError as e:
            logging.error(f"Environment variable error: {e}")
            raise RuntimeError("Failed to load environment variables. Check your .env file.") from e
        except Exception as e:
            logging.critical(f"Unexpected error while loading settings: {e}")
            raise RuntimeError("Critical error occurred in settings initialization.") from e

    def validate_env_vars(self):
        """Ensures required environment variables are properly set."""
        if not self.DB_USER or not self.DB_PASSWORD or not self.DB_HOST or not self.DB_NAME:
            raise ValueError("❌ Missing essential database configuration in environment variables.")

        if not self.SECRET_KEY:
            raise ValueError("❌ SECRET_KEY is missing. Ensure it is set in your environment variables.")

    @property
    def DATABASE_URL(self) -> str:
        """Constructs the database connection URL with exception handling."""
        try:
            return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        except Exception as e:
            logging.error(f"Error constructing DATABASE_URL: {e}")
            raise RuntimeError("Failed to construct database connection URL.") from e

# Create an instance of the settings
try:
    settings = Settings()
    logging.info("✅ Settings loaded successfully.")
except RuntimeError as e:
    logging.critical(f"❌ Failed to initialize application settings: {e}")
    raise
