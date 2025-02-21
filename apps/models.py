import logging
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, exc
from sqlalchemy.orm import relationship
from database import Base

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# User Role Model
class UserRole(Base):
    __tablename__ = "user_role"

    role_id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String(100), unique=True, nullable=False, index=True)

    users = relationship("UserMaster", back_populates="role", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<UserRole(role_id={self.role_id}, role_name={self.role_name})>"


# User Profession Model
class UserProfession(Base):
    __tablename__ = "user_profession"

    profession_id = Column(Integer, primary_key=True, autoincrement=True)
    profession_name = Column(String(100), unique=True, nullable=False, index=True)

    users = relationship("UserMaster", back_populates="profession", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<UserProfession(profession_id={self.profession_id}, profession_name={self.profession_name})>"


# User Registration Model (Temporary registration before activation)
class UserRegistration(Base):
    __tablename__ = "user_registration"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    user_mail = Column(String(255), unique=True, nullable=False, index=True)
    user_password = Column(String(255), nullable=False)
    user_number = Column(String(15), unique=True, nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("user_role.role_id", ondelete="CASCADE"), nullable=False)
    profession_id = Column(Integer, ForeignKey("user_profession.profession_id", ondelete="SET NULL"), nullable=True)
    country = Column(String(100), nullable=False)
    city = Column(String(100), nullable=False)
    registration_date = Column(DateTime, default=func.now())

    def __repr__(self):
        return f"<UserRegistration(id={self.id}, username={self.username}, user_mail={self.user_mail})>"


# User Master Model (Stores active user data)
class UserMaster(Base):
    __tablename__ = "user_master"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    user_mail = Column(String(255), unique=True, nullable=False, index=True)
    user_password = Column(String(255), nullable=False)
    user_number = Column(String(15), unique=True, nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("user_role.role_id", ondelete="CASCADE"), nullable=False)
    profession_id = Column(Integer, ForeignKey("user_profession.profession_id", ondelete="SET NULL"), nullable=True)
    country = Column(String(100), nullable=False)
    city = Column(String(100), nullable=False)
    registration_date = Column(DateTime, default=func.now())
    deregister_date = Column(DateTime, nullable=True)

    role = relationship("UserRole", back_populates="users")
    profession = relationship("UserProfession", back_populates="users")

    def __repr__(self):
        return f"<UserMaster(id={self.id}, username={self.username}, user_mail={self.user_mail})>"


# Registration Log Model (Tracks user registrations)
class RegistrationLog(Base):
    __tablename__ = "registration_log"

    log_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    user_mail = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("user_role.role_id", ondelete="CASCADE"), nullable=False)
    log_date = Column(DateTime, default=func.now())

    def __repr__(self):
        return f"<RegistrationLog(log_id={self.log_id}, username={self.username}, user_mail={self.user_mail})>"


# Function to handle database initialization
def initialize_database(engine):
    """
    Initializes the database by creating tables.
    Catches and logs errors if table creation fails.
    """
    try:
        Base.metadata.create_all(bind=engine)
        logging.info("✅ Database tables created successfully.")
    except exc.SQLAlchemyError as e:
        logging.error(f"❌ Error creating tables: {e}")
