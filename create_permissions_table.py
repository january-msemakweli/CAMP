from supabase import create_client, Client
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

def create_permissions_table():
    print("Creating form_permissions table...")
    
    # Use raw SQL for direct table creation
    sql = """
    CREATE TABLE IF NOT EXISTS public.form_permissions (
        id TEXT PRIMARY KEY,
        form_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(form_id, user_id)
    );
    
    -- Add foreign key constraints if they don't exist
    DO $$ 
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'form_permissions_form_id_fkey'
        ) THEN
            ALTER TABLE public.form_permissions
            ADD CONSTRAINT form_permissions_form_id_fkey
            FOREIGN KEY (form_id)
            REFERENCES public.forms(id)
            ON DELETE CASCADE;
        END IF;
        
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'form_permissions_user_id_fkey'
        ) THEN
            ALTER TABLE public.form_permissions
            ADD CONSTRAINT form_permissions_user_id_fkey
            FOREIGN KEY (user_id)
            REFERENCES public.users(id)
            ON DELETE CASCADE;
        END IF;
    END $$;
    """
    
    # Execute the SQL through Supabase
    try:
        # We need to use the PostgreSQL REST API directly
        print("Executing SQL to create form_permissions table...")
        # Try using a raw SQL query
        response = supabase.table("form_permissions").select("*").limit(1).execute()
        print("Table already exists.")
    except Exception as e:
        print(f"Caught exception: {str(e)}")
        
        # If the table doesn't exist, try to create it manually in the Supabase UI
        print("\nIMPORTANT: The form_permissions table doesn't exist.")
        print("Please create it manually in the Supabase dashboard SQL editor:")
        print("\n1. Login to your Supabase dashboard")
        print("2. Go to the SQL Editor")
        print("3. Copy and paste the SQL below:")
        print("\n" + sql)
        print("\n4. Execute the SQL query")
        print("5. Restart your Flask application after creating the table")

if __name__ == "__main__":
    create_permissions_table() 