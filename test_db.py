import psycopg2

def test_connection():
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="tinyurl",
            user="tinyurl_user",
            password="postgres",
            port="5432"
        )
        
        cur = conn.cursor()
        cur.execute("SELECT current_database(), current_user, version();")
        db_name, user_name, version = cur.fetchone()
        
        print(f"✅ Database: {db_name}")
        print(f"✅ User: {user_name}")
        print(f"✅ PostgreSQL: {version.split()[0]} {version.split()[1]}")
        
        cur.close()
        conn.close()
        print("✅ Connection successful!")
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_connection()