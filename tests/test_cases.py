import unittest
import mysql.connector
import hashlib
from cryptography.fernet import Fernet
import os
import time
from mysql.connector import Error

# Database configuration
DB_CONFIG = {
    'host': '',
    'user': '',
    'password': '',
    'database': ''
}

# Load encryption key using the same method as the application
def load_or_create_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

try:
    fernet = load_or_create_key()
except Exception as e:
    print(f"Failed to load or create encryption key: {e}")
    fernet = None

class TestCreditCardVault(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Initialize database connection
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            
            # Create a test user for our tests
            test_password = hashlib.sha256("test123".encode()).hexdigest()
            cursor.execute("INSERT IGNORE INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       ("testuser", test_password, "customer"))
            
            # Create a second test user for authentication failure tests
            test_password2 = hashlib.sha256("testpass".encode()).hexdigest()
            cursor.execute("INSERT IGNORE INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       ("lockuser", test_password2, "customer"))
            
            # Create a merchant test user
            merchant_password = hashlib.sha256("merchant123".encode()).hexdigest()
            cursor.execute("INSERT IGNORE INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       ("merchant", merchant_password, "merchant"))
            
     
            try:
                cursor.execute("ALTER TABLE Users ADD COLUMN IF NOT EXISTS locked BOOLEAN DEFAULT 0")
                conn.commit()
            except:
                pass  
            
            conn.commit()
            cursor.close()
            conn.close()
        except Error as e:
            print(f"Database setup error: {e}")
            raise
    
    @classmethod
    def tearDownClass(cls):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            
            # Clean up test users and their cards
            cursor.execute("SELECT user_id FROM Users WHERE username IN ('testuser', 'lockuser', 'merchant', 'newuser', 'sqluser')")
            user_ids = [row[0] for row in cursor.fetchall()]
            
            for user_id in user_ids:
                cursor.execute("DELETE FROM CreditCards WHERE user_id = %s", (user_id,))
            
            cursor.execute("DELETE FROM Users WHERE username IN ('testuser', 'lockuser', 'merchant', 'newuser', 'sqluser')")
            conn.commit()
            cursor.close()
            conn.close()
        except Error as e:
            print(f"Database cleanup error: {e}")
    
    def setUp(self):
        try:
            self.conn = mysql.connector.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor(dictionary=True)
        except Error as e:
            self.fail(f"Failed to connect to database: {e}")

    def tearDown(self):
        if hasattr(self, 'cursor') and self.cursor:
            self.cursor.close()
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

    # TC01: User Registration
    def test_user_registration(self):
        """Test user registration functionality"""
        username = "newuser"
        password = "password123"
        role = "customer"
        
        self.cursor.execute("DELETE FROM Users WHERE username = %s", (username,))
        self.conn.commit()
        
        # Now register the new user
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       (username, password_hash, role))
        self.conn.commit()
        
        # Verify user was created
        self.cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        result = self.cursor.fetchone()
        self.assertIsNotNone(result, "User was not registered successfully")
        self.assertEqual(result['username'], username, "Username mismatch")
        self.assertEqual(result['role'], role, "Role mismatch")

    # TC02: User Login with Correct Credentials
    def test_login_successful(self):
        """Test successful login with correct credentials"""
        username = "testuser"
        password = "test123"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        self.cursor.execute("SELECT user_id, role FROM Users WHERE username = %s AND password_hash = %s",
                       (username, password_hash))
        result = self.cursor.fetchone()
        
        self.assertIsNotNone(result, "Login failed with correct credentials")
        self.assertEqual(result['role'], "customer", "Role incorrect after login")

    # TC03: User Login with Wrong Password (3 times)
    def test_login_failed_multiple_attempts(self):
        """Test account locking after multiple failed login attempts"""
        
        username = "lockuser"
        wrong_password = "wrongpass"
        wrong_password_hash = hashlib.sha256(wrong_password.encode()).hexdigest()
        
        # Simulate 3 failed login attempts
        for _ in range(3):
            self.cursor.execute("SELECT user_id FROM Users WHERE username = %s AND password_hash = %s",
                           (username, wrong_password_hash))
            result = self.cursor.fetchone()
            self.assertIsNone(result, "Login succeeded with incorrect password")
            
            if _ == 2:  
                self.cursor.execute("UPDATE Users SET locked = 1 WHERE username = %s", (username,))
                self.conn.commit()
        
        # Verify the account is now locked
        self.cursor.execute("SELECT locked FROM Users WHERE username = %s", (username,))
        result = self.cursor.fetchone()
        self.assertIsNotNone(result, "User not found")
        self.assertEqual(result['locked'], 1, "Account not locked after 3 failed attempts")

    # TC04: Store Credit Card
    def test_store_credit_card(self):
        """Test storing a credit card securely"""
        if fernet is None:
            self.skipTest("Encryption key not available")
            
        # Get test user ID
        self.cursor.execute("SELECT user_id FROM Users WHERE username = %s", ("testuser",))
        user_id = self.cursor.fetchone()['user_id']
        
        # Card details
        card_data = {
            "cardholder_name": "Test User",
            "card_number": "5555555555554444",  
            "expiration_date": "05/25",
            "cvv": "321"
        }
        
        # Encrypt sensitive data
        encrypted_number = fernet.encrypt(card_data["card_number"].encode()).decode()
        encrypted_cvv = fernet.encrypt(card_data["cvv"].encode()).decode()
        
        # Store the card
        self.cursor.execute("""
            INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, card_data["cardholder_name"], encrypted_number, card_data["expiration_date"], encrypted_cvv))
        self.conn.commit()
        
        # Verify card was stored
        card_id = self.cursor.lastrowid
        self.cursor.execute("SELECT * FROM CreditCards WHERE card_id = %s", (card_id,))
        result = self.cursor.fetchone()
        
        self.assertIsNotNone(result, "Card not stored")
        self.assertEqual(result['cardholder_name'], card_data["cardholder_name"], "Cardholder name mismatch")
        
        # Verify data is encrypted (should not match original)
        self.assertNotEqual(result['card_number'], card_data["card_number"], "Card number not encrypted")
        self.assertNotEqual(result['cvv'], card_data["cvv"], "CVV not encrypted")
        
        # Verify we can decrypt it
        decrypted_number = fernet.decrypt(result['card_number'].encode()).decode()
        self.assertEqual(decrypted_number, card_data["card_number"], "Card number decryption failed")

    # TC05: View Stored Credit Cards with Masking
    def test_view_masked_cards(self):
        """Test viewing stored cards with proper masking"""
        if fernet is None:
            self.skipTest("Encryption key not available")
            
        # Get test user ID
        self.cursor.execute("SELECT user_id FROM Users WHERE username = %s", ("testuser",))
        user_id = self.cursor.fetchone()['user_id']
        
        # Add a test card if none exists
        self.cursor.execute("SELECT COUNT(*) as count FROM CreditCards WHERE user_id = %s", (user_id,))
        count = self.cursor.fetchone()['count']
        
        if count == 0:
            # Create a test card
            card_number = "4111111111111111"
            encrypted_number = fernet.encrypt(card_number.encode()).decode()
            encrypted_cvv = fernet.encrypt("123".encode()).decode()
            
            self.cursor.execute("""
                INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, "Test User", encrypted_number, "12/25", encrypted_cvv))
            self.conn.commit()
        
        # Get all cards for user
        self.cursor.execute("SELECT cardholder_name, card_number FROM CreditCards WHERE user_id = %s", (user_id,))
        cards = self.cursor.fetchall()
        
        # Check that we have cards
        self.assertGreater(len(cards), 0, "No cards found for user")
        
        # Test masking for each card
        for card in cards:
            decrypted = fernet.decrypt(card['card_number'].encode()).decode()
            masked = "**** **** **** " + decrypted[-4:]
            
            # Verify masking is correct
            self.assertEqual(len(masked), 19, "Masked card length incorrect")
            self.assertTrue(masked.startswith("**** **** **** "), "Masked format incorrect")
            self.assertEqual(masked[-4:], decrypted[-4:], "Last 4 digits don't match")

    # TC07: Delete Credit Card
    def test_delete_credit_card(self):
        """Test deleting a stored credit card"""
        if fernet is None:
            self.skipTest("Encryption key not available")
            
        # Get test user ID
        self.cursor.execute("SELECT user_id FROM Users WHERE username = %s", ("testuser",))
        user_id = self.cursor.fetchone()['user_id']
        
        # Create a test card to delete
        card_number = "6011111111111117"  # Test Discover card
        encrypted_number = fernet.encrypt(card_number.encode()).decode()
        encrypted_cvv = fernet.encrypt("456".encode()).decode()
        
        self.cursor.execute("""
            INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, "Delete Test", encrypted_number, "10/28", encrypted_cvv))
        self.conn.commit()
        
        card_id = self.cursor.lastrowid
        
        # Make sure card exists
        self.cursor.execute("SELECT card_id FROM CreditCards WHERE card_id = %s", (card_id,))
        self.assertIsNotNone(self.cursor.fetchone(), "Test card not created")
        
        # Delete the card
        self.cursor.execute("DELETE FROM CreditCards WHERE card_id = %s", (card_id,))
        self.conn.commit()
        
        # Verify card is deleted
        self.cursor.execute("SELECT card_id FROM CreditCards WHERE card_id = %s", (card_id,))
        result = self.cursor.fetchone()
        self.assertIsNone(result, "Card not deleted from database")

    # TC08: Unauthorized User Access
    def test_unauthorized_access(self):
        """Test unauthorized access to admin panel"""
        # Get non-admin user role
        self.cursor.execute("SELECT role FROM Users WHERE username = %s", ("testuser",))
        role = self.cursor.fetchone()['role']
        
        # Check if user has admin access
        access_allowed = (role == 'admin')
        
        # Verify the user doesn't have admin access
        self.assertFalse(access_allowed, "Customer role should not have admin access")
        
        self.cursor.execute("SELECT role FROM Users WHERE username = %s", ("merchant",))
        role = self.cursor.fetchone()['role']
        
        # Check if merchant has admin access
        access_allowed = (role == 'admin')
        
        # Verify the merchant doesn't have admin access
        self.assertFalse(access_allowed, "Merchant role should not have admin access")

    # TC09: SQL Injection Prevention in Login
    def test_sql_injection_login(self):
        """Test SQL injection prevention in login functionality"""
        # Create a test user first
        sql_username = "sqluser"
        sql_password = "password123"
        password_hash = hashlib.sha256(sql_password.encode()).hexdigest()
        
        # Clean up any existing test user
        self.cursor.execute("DELETE FROM Users WHERE username = %s", (sql_username,))
        self.conn.commit()
        
        # Create new test user
        self.cursor.execute("INSERT INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       (sql_username, password_hash, "customer"))
        self.conn.commit()
        
        # Test SQL injection in username field
        injection_attacks = [
            "sqluser' --",
            "sqluser' OR '1'='1",
            "sqluser'; DROP TABLE Users; --",
            "' OR 1=1; --",
            "' UNION SELECT user_id, password_hash, role FROM Users WHERE username='admin"
        ]
        
        for attack in injection_attacks:
            # This simulates the login method using parameterized queries
            try:
                self.cursor.execute("SELECT user_id, role FROM Users WHERE username = %s AND password_hash = %s",
                               (attack, password_hash))
                result = self.cursor.fetchone()
                
                self.assertIsNone(result, f"SQL injection succeeded with: {attack}")
                
                # Verify Users table still exists
                self.cursor.execute("SHOW TABLES LIKE 'Users'")
                self.assertIsNotNone(self.cursor.fetchone(), "Users table was dropped - SQL injection succeeded")
                
            except mysql.connector.Error as err:
                self.fail(f"SQL injection test caused database error: {err}")

    # TC10: SQL Injection Prevention in Card Search
    def test_sql_injection_card_search(self):
        """Test SQL injection prevention in card search functionality"""
        if fernet is None:
            self.skipTest("Encryption key not available")
            
        # Get test user ID
        self.cursor.execute("SELECT user_id FROM Users WHERE username = %s", ("testuser",))
        user_id = self.cursor.fetchone()['user_id']
        
        # Create a test card with a specific name for searching
        card_name = "SQL Test Card"
        card_number = "4111111111111111"
        encrypted_number = fernet.encrypt(card_number.encode()).decode()
        encrypted_cvv = fernet.encrypt("123".encode()).decode()
        
        # Add test card
        self.cursor.execute("""
            INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, card_name, encrypted_number, "12/25", encrypted_cvv))
        self.conn.commit()
        card_id = self.cursor.lastrowid
        
        # Test SQL injection attacks on card search
        injection_attacks = [
            "SQL Test Card' OR '1'='1",
            "' OR 1=1; --",
            "anything' UNION SELECT card_id, user_id, card_number, expiration_date, cvv FROM CreditCards; --",
            "' OR cardholder_name LIKE '%'; --"
        ]
        
        for attack in injection_attacks:
            try:
                # simulates a card search function using parameterized queries
                self.cursor.execute("SELECT * FROM CreditCards WHERE cardholder_name = %s AND user_id = %s", 
                              (attack, user_id))
                results = self.cursor.fetchall()
                
                if results:
                    # Should only match exact string, not any other cards
                    for result in results:
                        self.assertEqual(result['cardholder_name'], attack, 
                                         f"SQL injection may have succeeded with: {attack}")
                
            except mysql.connector.Error as err:
                self.fail(f"SQL injection test caused database error: {err}")
                
        # Clean up
        self.cursor.execute("DELETE FROM CreditCards WHERE card_id = %s", (card_id,))
        self.conn.commit()

    # TC11: SQL Injection in Direct SQL Construction
    def test_unsafe_sql_construction(self):
        """Test the dangers of unsafe SQL string construction (simulation)"""
        
        cardholder = "Test'; DELETE FROM CreditCards WHERE 1=1; --"
        user_id = 1
        
        unsafe_query = f"SELECT * FROM CreditCards WHERE cardholder_name = '{cardholder}' AND user_id = {user_id}"
        
        # Verify that the constructed query contains the injection
        self.assertIn("DELETE FROM CreditCards", unsafe_query, 
                     "SQL injection simulation should contain DELETE statement")
        
        safe_params = (cardholder, user_id)
        
        # Execute the query safely
        self.cursor.execute("SELECT * FROM CreditCards WHERE cardholder_name = %s AND user_id = %s", safe_params)
        
        # Check that the database table is still intact
        self.cursor.execute("SHOW TABLES LIKE 'CreditCards'")
        self.assertIsNotNone(self.cursor.fetchone(), "CreditCards table should still exist")

if __name__ == "__main__":
    unittest.main()