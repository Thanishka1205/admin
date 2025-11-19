"""
Script to create the tab_switches table in the database
Run this script once to set up the table before using tab switch monitoring
"""

from db_config import get_db_connection

def create_tab_switches_table():
    """Create the tab_switches table if it doesn't exist"""
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database!")
        return False
    
    try:
        cursor = conn.cursor()
        
        # Create table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tab_switches (
                switch_id INT AUTO_INCREMENT PRIMARY KEY,
                candidate_id INT NOT NULL,
                attempt_number INT NOT NULL,
                switch_type ENUM('switch_out', 'switch_back') NOT NULL,
                switched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (candidate_id) REFERENCES candidates(id) ON DELETE CASCADE,
                INDEX idx_candidate_attempt (candidate_id, attempt_number),
                INDEX idx_switched_at (switched_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        
        conn.commit()
        print("✓ tab_switches table created successfully!")
        
        # Verify table exists
        cursor.execute("SHOW TABLES LIKE 'tab_switches'")
        if cursor.fetchone():
            print("✓ Table verified in database")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Error creating table: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    print("Creating tab_switches table...")
    success = create_tab_switches_table()
    if success:
        print("\nTable setup completed successfully!")
    else:
        print("\nTable setup failed. Please check the error above.")

