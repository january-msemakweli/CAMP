from supabase import create_client, Client
from dotenv import load_dotenv
import os
from app import supabase, create_tables

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

def create_tables():
    # Create users table
    supabase.table('users').create({
        'id': 'uuid primary key',
        'username': 'text unique not null',
        'password': 'text not null',
        'is_admin': 'boolean default false',
        'is_approved': 'boolean default false',
        'created_at': 'timestamp with time zone default now()'
    }).execute()

    # Create projects table
    supabase.table('projects').create({
        'id': 'uuid primary key',
        'name': 'text not null',
        'created_at': 'timestamp with time zone default now()'
    }).execute()

    # Create forms table
    supabase.table('forms').create({
        'id': 'uuid primary key',
        'project_id': 'uuid references projects(id)',
        'title': 'text not null',
        'fields': 'jsonb not null',
        'created_at': 'timestamp with time zone default now()'
    }).execute()

    # Create form_submissions table (generic table for all form submissions)
    supabase.table('form_submissions').create({
        'id': 'uuid primary key',
        'form_id': 'uuid references forms(id)',
        'patient_id': 'text not null',
        'submitted_by': 'uuid references users(id)',
        'data': 'jsonb not null',
        'created_at': 'timestamp with time zone default now()'
    }).execute()

    print("Database tables created successfully!")

def initialize_database():
    print("Initializing database...")
    create_tables()
    print("Database initialization complete!")

if __name__ == "__main__":
    initialize_database() 