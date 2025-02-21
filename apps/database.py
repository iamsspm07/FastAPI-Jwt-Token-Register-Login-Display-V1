import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from urllib.parse import quote_plus
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

try:
    # Database Configuration
    DB_CONFIG = {
        "user": os.getenv("DB_USER"),
        "password": quote_plus(os.getenv("DB_PASSWORD") or ""),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "3306"),
        "name": os.getenv("DB_NAME"),
    }

    # Validate database credentials
    if not all(DB_CONFIG.values()):
        raise ValueError("❌ Missing required database environment variables.")

    # Create Database URL
    DATABASE_URL = f"mysql+mysqlconnector://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['name']}"

    # Initialize Engine with Exception Handling
    engine = create_engine(
        DATABASE_URL,
        pool_size=20,
        max_overflow=50,
        pool_timeout=60,
        pool_recycle=3600,
        echo=False,
        pool_pre_ping=True,  # Checks connection health before using it
    )

    # SQLAlchemy Session & Base
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()

    logging.info("✅ Database connection initialized successfully.")

except ValueError as ve:
    logging.critical(f"Environment Variable Error: {ve}")
    raise RuntimeError("Database configuration is invalid. Please check the .env file.") from ve

except SQLAlchemyError as se:
    logging.critical(f"SQLAlchemy Engine Error: {se}")
    raise RuntimeError("Failed to initialize database engine.") from se

except Exception as e:
    logging.critical(f"Unexpected Error: {e}")
    raise RuntimeError("An unexpected error occurred during database initialization.") from e


# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as e:
        logging.error(f"Database session error: {e}")
        raise RuntimeError("Database session error occurred.") from e
    finally:
        db.close()
        logging.info("✅ Database session closed.")
