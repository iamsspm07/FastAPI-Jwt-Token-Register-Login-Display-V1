import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from models import UserRegistration, UserMaster, RegistrationLog, UserRole, UserProfession
from utils import hash_password, verify_password
from fastapi import HTTPException

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def create_user(db: Session, user_data):
    """Creates a new user and logs the registration process."""
    try:
        # Hash the password before storing
        user_data.password = hash_password(user_data.password)

        # Fetch Role and Profession IDs
        role = db.query(UserRole).filter_by(role_name=user_data.role).first()
        profession = db.query(UserProfession).filter_by(profession_name=user_data.profession).first()

        if not role or not profession:
            logging.warning("❌ Invalid role or profession provided.")
            return {"error": "Invalid role or profession."}

        # Create User Registration entry
        new_registration = UserRegistration(
            username=user_data.username,
            user_mail=user_data.email,
            user_password=user_data.password,
            user_number=user_data.phone,
            role_id=role.role_id,
            profession_id=profession.profession_id,
            country=user_data.country,
            city=user_data.city
        )
        db.add(new_registration)
        db.flush()  # Ensures registration ID is available

        # Create User Master entry
        new_user_master = UserMaster(
            username=user_data.username,
            user_mail=user_data.email,
            user_password=user_data.password,
            user_number=user_data.phone,
            role_id=role.role_id,
            profession_id=profession.profession_id,
            country=user_data.country,
            city=user_data.city
        )
        db.add(new_user_master)

        # Create Registration Log entry
        new_registration_log = RegistrationLog(
            username=user_data.username,
            user_mail=user_data.email,
            role_id=role.role_id
        )
        db.add(new_registration_log)

        # Commit transaction
        db.commit()
        logging.info(f"✅ User '{user_data.username}' registered successfully.")
        return {"success": f"User registered with ID {new_registration.id}"}

    except IntegrityError as e:
        db.rollback()
        logging.error(f"❌ Integrity Error: {e.orig}")
        return {"error": "User already exists or invalid foreign key reference."}
    except SQLAlchemyError as e:
        db.rollback()
        logging.error(f"🔥 Database Error: {e}")
        return {"error": "Database error occurred."}
    except Exception as e:
        db.rollback()
        logging.critical(f"🚨 Unexpected Error: {e}")
        return {"error": "Unexpected error occurred."}


def authenticate_user(db: Session, email: str, password: str):
    """Authenticates a user based on email and password."""
    try:
        user = db.query(UserMaster).filter_by(user_mail=email).first()

        if user and verify_password(password, user.user_password):
            logging.info(f"✅ Authentication successful for user: {email}")
            return user

        logging.warning(f"❌ Authentication failed for user: {email}")
        return {"error": "Invalid email or password."}

    except SQLAlchemyError as e:
        logging.error(f"🔥 Database Error during authentication: {e}")
        return {"error": "Database error occurred."}
    except Exception as e:
        logging.critical(f"🚨 Unexpected Error during authentication: {e}")
        return {"error": "Unexpected error occurred."}


def delete_user_by_phone(db: Session, phone_number: str):
    """Deletes a user and related records using their phone number."""
    try:
        user_reg = db.query(UserRegistration).filter_by(user_number=phone_number).first()
        user_master = db.query(UserMaster).filter_by(user_number=phone_number).first()

        if not user_reg and not user_master:
            logging.warning(f"❌ No user found with phone number: {phone_number}")
            return {"error": "User not found."}

        # Delete user records
        if user_reg:
            user_log = db.query(RegistrationLog).filter_by(user_mail=user_reg.user_mail).first()
            db.delete(user_reg)
            if user_log:
                db.delete(user_log)

        if user_master:
            db.delete(user_master)

        db.commit()
        logging.info(f"✅ User with phone number '{phone_number}' deleted successfully.")
        return {"success": f"User with phone number '{phone_number}' deleted."}

    except SQLAlchemyError as e:
        db.rollback()
        logging.error(f"🔥 Database Error during deletion: {e}")
        return {"error": "Database error occurred while deleting user."}
    except Exception as e:
        db.rollback()
        logging.critical(f"🚨 Unexpected Error during deletion: {e}")
        return {"error": "Unexpected error occurred while deleting user."}


def get_all_users(db: Session):
    """Fetches all users from the UserMaster table."""
    try:
        users = db.query(UserMaster).all()

        if not users:
            logging.info("ℹ No users found in the database.")
            return []

        return users

    except SQLAlchemyError as e:
        logging.error(f"🔥 Database error while fetching users: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred.")
    except Exception as e:
        logging.error(f"🚨 Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


def get_all_users_register(db: Session):
    """Fetches all users from the UserRegistration table."""
    try:
        users = db.query(UserRegistration).all()

        if not users:
            logging.info("ℹ No registered users found in the database.")
            return []

        return users

    except SQLAlchemyError as e:
        logging.error(f"🔥 Database error while fetching registered users: {str(e)}")
        raise HTTPException(status_code=500, detail="Database error occurred.")
    except Exception as e:
        logging.error(f"🚨 Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")
