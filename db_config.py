import mysql.connector
from mysql.connector import Error
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

def get_db_connection():
    """Get a database connection with proper error handling"""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'candidate_assessment'),
            autocommit=False,
            connect_timeout=10,
            buffered=True
        )
        if conn.is_connected():
            return conn
    except Error as e:
        logger.error(f"Error connecting to MySQL database: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error connecting to database: {e}")
        raise
