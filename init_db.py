#!/usr/bin/env python

import os
from supabase import create_client, Client
from dotenv import load_dotenv
import uuid
from werkzeug.security import generate_password_hash
import sys

# Load environment variables
load_dotenv()

def initialize_database():
    """Initialize the database with required tables and admin user"""
    try:
        print("Initializing database...")
        
        # Initialize Supabase client
        supabase: Client = create_client(
            os.getenv('SUPABASE_URL'),
            os.getenv('SUPABASE_KEY')
        )
        
        # Test connection
        try:
            supabase.table('users').select('id').limit(1).execute()
            print("Connected to Supabase successfully.")
        except Exception as e:
            print(f"Error connecting to Supabase: {str(e)}")
            print("Please check your SUPABASE_URL and SUPABASE_KEY environment variables.")
            return
        
        # Run SQL file for patients table fix
        with open('fix_simple.sql', 'r') as f:
            sql_patients = f.read()
            print("\nFixing patients table...")
            print("SQL would be executed through database client.")
            print("Please run the SQL file manually in your database client.")
            
        # Run SQL file for project access
        with open('fix_project_access.sql', 'r') as f:
            sql_project_access = f.read()
            print("\nCreating project access table...")
            print("SQL would be executed through database client.")
            print("Please run the SQL file manually in your database client.")
        
        # Check if admin user exists
        response = supabase.table('users').select('*').eq('username', 'admin').execute()
        
        if not response.data:
            print("\nAdmin user not found, creating...")
            try:
                # Create admin user
                admin_user = {
                    'id': str(uuid.uuid4()),
                    'username': 'admin',
                    'password': generate_password_hash('moafya123'),
                    'is_admin': True,
                    'is_approved': True
                }
                supabase.table('users').insert(admin_user).execute()
                print("Admin user created successfully!")
                print("Username: admin")
                print("Password: moafya123")
            except Exception as e:
                print(f"Error creating admin user: {str(e)}")
        else:
            print("\nAdmin user already exists.")
        
        print("\nDatabase initialization completed.")
        print("For more detailed setup, please run the SQL files manually in your database client.")
        print("SQL files to execute:")
        print("- fix.sql: Complete database setup with all tables")
        print("- fix_simple.sql: Quick fix for the patients table")
        print("- fix_project_access.sql: Adds project access control")
        
    except Exception as e:
        print(f"Error initializing database: {str(e)}")

if __name__ == "__main__":
    initialize_database() 