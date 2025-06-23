from dotenv import load_dotenv
import os
from supabase import create_client, Client

# Load environment variables
load_dotenv()

def add_show_waitlist_column():
    """
    Migration script to add the show_waitlist column to existing forms.
    This script should be run once after updating the schema.sql file.
    """
    # Check for required environment variables
    if not os.getenv('SUPABASE_URL') or not os.getenv('SUPABASE_KEY'):
        print("Error: SUPABASE_URL and SUPABASE_KEY environment variables are required.")
        return False
    
    try:
        # Initialize Supabase client
        supabase: Client = create_client(
            os.getenv('SUPABASE_URL'),
            os.getenv('SUPABASE_KEY')
        )
        
        print("Connected to Supabase...")
        
        # Check if the column already exists
        try:
            # Try a query that uses the column to see if it exists
            supabase.table('forms').select('show_waitlist').limit(1).execute()
            print("show_waitlist column already exists in forms table.")
            return True
        except Exception:
            print("show_waitlist column doesn't exist yet. Adding it now...")
        
        # Use PostgreSQL query to add the new column
        # Note: This requires the supabase-js client version that supports rpc calls
        result = supabase.rpc('add_show_waitlist_column', {}).execute()
        print("Column added successfully.")
        
        # Set all existing forms show_waitlist to False by default
        update_result = supabase.table('forms').update({'show_waitlist': False}).execute()
        print(f"Updated {len(update_result.data) if update_result.data else 0} existing forms to set show_waitlist=False")
        
        return True
        
    except Exception as e:
        print(f"Error adding show_waitlist column: {str(e)}")
        return False

if __name__ == "__main__":
    print("Starting migration to add show_waitlist column to forms table...")
    success = add_show_waitlist_column()
    
    if success:
        print("Migration completed successfully!")
    else:
        print("Migration failed. Check the error messages above.")
        
    print("\nIf the column wasn't added automatically, run this SQL command directly on your database:")
    print("ALTER TABLE public.forms ADD COLUMN IF NOT EXISTS show_waitlist BOOLEAN DEFAULT FALSE;") 