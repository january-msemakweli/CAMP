from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from dotenv import load_dotenv
import os
from datetime import datetime, timezone, timedelta
import uuid
import json
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
import base64
from io import BytesIO, StringIO
import time
import re
from collections import Counter

# Set default timezone to GMT+3 (East African Time)
EAT = timezone(timedelta(hours=3))

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv('SUPABASE_URL'),
    os.getenv('SUPABASE_KEY')
)

# Add a template filter to convert timestamps to EAT
@app.template_filter('to_eat')
def to_eat_filter(timestamp):
    """Convert a UTC timestamp to EAT timezone in templates"""
    return utc_to_eat(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else ''

def create_tables():
    try:
        print("Attempting to create database tables...")
        # Check if tables exist first (optional, but good practice)
        # ... (existing checks or logic can go here)

        # Execute raw SQL to create tables and add columns if they don't exist
        sql = """
        -- Drop existing foreign key constraints if they exist
        DO $$ 
        BEGIN
            BEGIN
                ALTER TABLE public.forms DROP CONSTRAINT IF EXISTS forms_project_id_fkey;
            EXCEPTION
                WHEN undefined_table THEN NULL;
            END;
            
            BEGIN
                ALTER TABLE public.form_submissions DROP CONSTRAINT IF EXISTS form_submissions_form_id_fkey;
            EXCEPTION
                WHEN undefined_table THEN NULL;
            END;
            
            BEGIN
                ALTER TABLE public.form_submissions DROP CONSTRAINT IF EXISTS form_submissions_submitted_by_fkey;
            EXCEPTION
                WHEN undefined_table THEN NULL;
            END;
            
            BEGIN
                ALTER TABLE public.form_permissions DROP CONSTRAINT IF EXISTS form_permissions_form_id_fkey;
            EXCEPTION
                WHEN undefined_table THEN NULL;
            END;
            
            BEGIN
                ALTER TABLE public.form_permissions DROP CONSTRAINT IF EXISTS form_permissions_user_id_fkey;
            EXCEPTION
                WHEN undefined_table THEN NULL;
            END;
        END $$;

        CREATE TABLE IF NOT EXISTS public.users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            is_approved BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS public.projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS public.forms (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            title TEXT NOT NULL,
            fields JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS public.form_submissions (
            id TEXT PRIMARY KEY,
            form_id TEXT,
            patient_id TEXT NOT NULL,
            submitted_by TEXT,
            data JSONB NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS public.form_permissions (
            id TEXT PRIMARY KEY,
            form_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(form_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS public.log_activities (
            id TEXT PRIMARY KEY,
            user_id TEXT REFERENCES public.users(id) ON DELETE SET NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Add foreign key constraints with ON DELETE CASCADE
        ALTER TABLE public.forms 
        ADD CONSTRAINT forms_project_id_fkey 
        FOREIGN KEY (project_id) 
        REFERENCES public.projects(id) 
        ON DELETE CASCADE;

        ALTER TABLE public.form_submissions 
        ADD CONSTRAINT form_submissions_form_id_fkey 
        FOREIGN KEY (form_id) 
        REFERENCES public.forms(id) 
        ON DELETE CASCADE;

        ALTER TABLE public.form_submissions 
        ADD CONSTRAINT form_submissions_submitted_by_fkey 
        FOREIGN KEY (submitted_by) 
        REFERENCES public.users(id) 
        ON DELETE SET NULL;
        
        ALTER TABLE public.form_permissions
        ADD CONSTRAINT form_permissions_form_id_fkey
        FOREIGN KEY (form_id)
        REFERENCES public.forms(id)
        ON DELETE CASCADE;
        
        ALTER TABLE public.form_permissions
        ADD CONSTRAINT form_permissions_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.users(id)
        ON DELETE CASCADE;
        """
        try:
            supabase.rpc('execute_sql', {'sql': sql}).execute()
            print("Database tables and columns ensured successfully using raw SQL")
        except Exception as sql_error:
            print(f"Error ensuring tables/columns with raw SQL: {str(sql_error)}")

    except Exception as e:
        print(f"Error in create_tables function: {str(e)}")

def ensure_admin_user():
    try:
        print("Checking for admin user...")
        # Create tables first
        create_tables()
        
        # Check if admin user exists
        response = supabase.table('users').select('*').eq('username', 'admin').execute()
        if not response.data:
            print("Admin user not found, creating...")
            # Create admin user if it doesn't exist
            admin_user = {
                'id': str(uuid.uuid4()),
                'username': 'admin',
                'password': generate_password_hash('moafya123'),
                'is_admin': True,
                'is_approved': True
            }
            supabase.table('users').insert(admin_user).execute()
            print("Admin user created successfully")
        else:
            print("Admin user already exists")
    except Exception as e:
        print(f"Error ensuring admin user: {str(e)}")

def check_database_structure():
    try:
        # Check form_submissions table
        response = supabase.table('form_submissions').select('*').limit(1).execute()
        print("form_submissions table exists:", bool(response.data))
        
        # Check forms table
        response = supabase.table('forms').select('*').limit(1).execute()
        print("forms table exists:", bool(response.data))
        
        # Check projects table
        response = supabase.table('projects').select('*').limit(1).execute()
        print("projects table exists:", bool(response.data))
        
        # Check users table
        response = supabase.table('users').select('*').limit(1).execute()
        print("users table exists:", bool(response.data))
        
    except Exception as e:
        print("Error checking database structure:", str(e))

def log_activity(action, entity_type, entity_id=None, details=None):
    """
    Records user activity in the database
    
    Parameters:
    - action: The action performed (e.g., 'create', 'update', 'delete', 'view')
    - entity_type: The type of entity (e.g., 'project', 'form', 'user', 'submission')
    - entity_id: Optional ID of the affected entity
    - details: Optional additional details about the action
    """
    try:
        # Skip logging if action is 'view'
        if action == 'view':
            return
            
        if current_user.is_authenticated:
            # Get current timestamp in EAT timezone
            current_time = datetime.now(EAT)
            
            log_entry = {
                'id': str(uuid.uuid4()),
                'user_id': current_user.id,
                'username': current_user.username,
                'action': action,
                'entity_type': entity_type,
                'entity_id': entity_id,
                'details': details,
                'ip_address': request.remote_addr,
                # Let the database handle timestamp conversion; it's aware of timezones
                # 'created_at': current_time.isoformat()
            }
            supabase.table('log_activities').insert(log_entry).execute()
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

# Ensure admin user exists when app starts
ensure_admin_user()

# Check database structure
check_database_structure()

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

class User(UserMixin):
    def __init__(self, id, username, is_admin=False, is_approved=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.is_approved = is_approved

@login_manager.user_loader
def load_user(user_id):
    try:
        print(f"Loading user: {user_id}")
        # Fetch user from Supabase
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        if response.data:
            user_data = response.data[0]
            print(f"User found: {user_data['username']}")
            return User(
                id=user_data['id'],
                username=user_data['username'],
                is_admin=user_data['is_admin'],
                is_approved=user_data['is_approved']
            )
        print(f"User not found: {user_id}")
        return None
    except Exception as e:
        print(f"Error loading user: {str(e)}")
        return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard' if not current_user.is_admin else 'admin_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if username exists
        response = supabase.table('users').select('*').eq('username', username).execute()
        if response.data:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = {
            'id': str(uuid.uuid4()),
            'username': username,
            'password': hashed_password,
            'is_admin': False,
            'is_approved': False
        }
        
        supabase.table('users').insert(new_user).execute()
        
        # Create a temporary user object to log user registration
        temp_user = User(
            id=new_user['id'],
            username=new_user['username'],
            is_admin=False,
            is_approved=False
        )
        
        # Use Flask-Login's _get_current_object method to get app context
        with app.app_context():
            # Manually set the user for this operation only
            previous_user = getattr(current_user, '_get_current_object', lambda: None)()
            try:
                # Log registration as system action since user isn't logged in yet
                log_entry = {
                    'id': str(uuid.uuid4()),
                    'user_id': new_user['id'],
                    'username': new_user['username'],
                    'action': 'register',
                    'entity_type': 'user',
                    'entity_id': new_user['id'],
                    'details': "New user registration (pending approval)",
                    'ip_address': request.remote_addr
                }
                supabase.table('log_activities').insert(log_entry).execute()
            except Exception as e:
                print(f"Error logging registration: {str(e)}")
        
        flash('Registration successful! Please wait for admin approval.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill in all fields.', 'danger')
            return render_template('login.html')
        
        # Fetch user from database
        try:
            response = supabase.table('users').select('*').eq('username', username).execute()
            if response.data and len(response.data) > 0:
                user_data = response.data[0]
                
                # Check if account is approved
                if not user_data.get('is_approved', False):
                    flash('Your account is pending approval. Please contact an administrator.', 'warning')
                    return render_template('login.html')
                
                # Verify password
                if check_password_hash(user_data['password'], password):
                    # Create user object
                    user = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        is_admin=user_data.get('is_admin', False),
                        is_approved=user_data.get('is_approved', False)
                    )
                    login_user(user)
                    
                    log_activity('login', 'user', user_data['id'])
                    
                    # Redirect based on user role
                    if user.is_admin:
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('user_dashboard'))
                else:
                    flash('Invalid username or password. Please try again.', 'danger')
            else:
                flash('Invalid username or password. Please try again.', 'danger')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else None
    
    logout_user()
    
    # Log the logout action after the user is logged out
    if user_id and username:
        try:
            log_entry = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'username': username,
                'action': 'logout',
                'entity_type': 'user',
                'entity_id': user_id,
                'ip_address': request.remote_addr
            }
            supabase.table('log_activities').insert(log_entry).execute()
        except Exception as e:
            print(f"Error logging logout activity: {str(e)}")
    
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get pending users
    response = supabase.table('users').select('*').eq('is_approved', False).execute()
    pending_users = response.data
    
    # Get all users
    all_users_response = supabase.table('users').select('*').execute()
    all_users = all_users_response.data
    
    # Get all projects
    projects_response = supabase.table('projects').select('*').execute()
    projects = projects_response.data
    
    return render_template('admin_dashboard.html', 
                         pending_users=pending_users,
                         all_users=all_users,
                         projects=projects)

@app.route('/admin/approve_user/<user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get user info for logging
    user_response = supabase.table('users').select('username').eq('id', user_id).execute()
    username = user_response.data[0]['username'] if user_response.data else "Unknown user"
    
    supabase.table('users').update({'is_approved': True}).eq('id', user_id).execute()
    
    log_activity('approve', 'user', user_id, f"Approved user: {username}")
    flash('User approved successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get user info for logging
    user_response = supabase.table('users').select('username').eq('id', user_id).execute()
    username = user_response.data[0]['username'] if user_response.data else "Unknown user"
    
    supabase.table('users').delete().eq('id', user_id).execute()
    
    log_activity('delete', 'user', user_id, f"Deleted user: {username}")
    flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_project', methods=['POST'])
@login_required
def create_project():
    if not current_user.is_admin:
        flash('You do not have permission to create projects.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Extract form data
    name = request.form.get('name')
    # camp_date = request.form.get('camp_date') # Removed camp_date

    # if not name or not camp_date: # Updated condition
    if not name: 
        flash('Please fill in all required fields.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Create new project
    try:
        project_id = str(uuid.uuid4())
        project_data = {
            'id': project_id,
            'name': name,
            # 'camp_date': camp_date # Removed camp_date
        }
        
        # Insert into database
        response = supabase.table('projects').insert(project_data).execute()
        
        if response.data:
            log_activity('create', 'project', project_id, f"Project name: {name}")
            flash('Project created successfully.', 'success')
        else:
            flash('Failed to create project.', 'danger')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_project/<project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete projects.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get project details before deleting (for logging)
    try:
        # Get project info
        project_response = supabase.table('projects').select('*').eq('id', project_id).execute()
        if not project_response.data:
            flash('Project not found', 'danger')
            return redirect(url_for('admin_dashboard'))
            
        project_name = project_response.data[0]['name']
        
        # First get all forms for this project
        forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        form_ids = [form['id'] for form in forms_response.data]
        
        # For each form, delete related permissions
        for form_id in form_ids:
            supabase.table('form_permissions').delete().eq('form_id', form_id).execute()
        
        # For each form, delete submissions
        for form_id in form_ids:
            supabase.table('form_submissions').delete().eq('form_id', form_id).execute()
        
        # Delete all forms
        if form_ids:
            supabase.table('forms').delete().eq('project_id', project_id).execute()
        
        # Finally, delete the project
        project_delete_response = supabase.table('projects').delete().eq('id', project_id).execute()
        
        # Log the deletion
        log_activity('delete', 'project', project_id, f"Project name: {project_name}")
        flash('Project deleted successfully.', 'success')
        
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/project/<project_id>')
@login_required
def project_detail(project_id):
    # Get project details
    project_response = supabase.table('projects').select('*').eq('id', project_id).execute()
    if not project_response.data:
        flash('Project not found')
        return redirect(url_for('user_dashboard' if not current_user.is_admin else 'admin_dashboard'))
    
    project = project_response.data[0]
    # Remove camp_date if it exists in the fetched data, though it shouldn't anymore
    project.pop('camp_date', None) 
    
    # Get forms for this project
    forms_response = supabase.table('forms').select('*').eq('project_id', project_id).execute()
    forms = forms_response.data
    
    # Get submission count for each form and parse fields
    for form in forms:
        submissions_response = supabase.table('form_submissions').select('id').eq('form_id', form['id']).execute()
        form['submissions_count'] = len(submissions_response.data)
        
        # Parse the fields JSON string into Python objects
        if isinstance(form['fields'], str):
            try:
                form['fields'] = json.loads(form['fields'])
            except Exception as e:
                print(f"Error parsing fields for form {form['id']}: {str(e)}")
                form['fields'] = []
        
        # If fields is still not a list, initialize it as an empty list
        if not isinstance(form['fields'], list):
            print(f"Form fields not a list for form {form['id']}: {type(form['fields'])}")
            form['fields'] = []
        
        # If admin, get users with access to this form
        if current_user.is_admin:
            # Get all permissions for this form
            permissions_response = supabase.table('form_permissions').select('*').eq('form_id', form['id']).execute()
            permissions = permissions_response.data
            
            # Get user details separately for each permission
            form['user_permissions'] = []
            for permission in permissions:
                user_response = supabase.table('users').select('username').eq('id', permission['user_id']).execute()
                if user_response.data:
                    # Add user info to the permission object
                    permission['users'] = user_response.data[0]
                    form['user_permissions'].append(permission)
    
    # Log project detail view
    log_activity('view', 'project', project_id, f"Project: {project['name']}")
    
    return render_template('project_detail.html', project=project, forms=forms)

@app.route('/project/<project_id>/create_form', methods=['POST'])
@login_required
def create_form(project_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        title = request.form.get('title')
        labels = request.form.getlist('field_labels[]')
        types = request.form.getlist('field_types[]')
        options_list = request.form.getlist('field_options[]')
        location_identifiers = request.form.getlist('location_field_identifier[]') # Read the identifiers
        
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        if not labels:
            flash('At least one field is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        
        fields = []
        # Track location identifiers used to map them correctly
        location_idx = 0 
        for i in range(len(labels)):
            field = {
                'label': labels[i].strip(),
                'type': types[i],
                'options': [opt.strip() for opt in options_list[i].split(',') if opt.strip()] if types[i] in ['dropdown', 'radio', 'checkbox'] else []
            }
            # Check if this label corresponds to a location field identifier
            # This assumes location fields are added together and in order
            # A more robust approach might involve matching based on label, but this works with current JS
            if labels[i] in ['Region', 'District', 'Ward'] and location_idx < len(location_identifiers): 
                 field['location_field_identifier'] = location_identifiers[location_idx]
                 # Ensure type is dropdown for location fields, even if JS fails
                 field['type'] = 'dropdown' 
                 field['options'] = [] # Options are dynamic
                 location_idx += 1
            else:
                 field['location_field_identifier'] = None

            fields.append(field)
            
        # Print fields before serialization
        print(f"Fields before JSON serialization: {fields}")
        serialized_fields = json.dumps(fields)
        print(f"Serialized fields: {serialized_fields}")
        
        # Create form record
        form_id = str(uuid.uuid4())
        form_data = {
            'id': form_id,
            'project_id': project_id,
            'title': title,
            'fields': serialized_fields
        }
        
        print(f"Form data to be inserted: {form_data}")
        response = supabase.table('forms').insert(form_data).execute()
        print(f"Insert response: {response.data}")
        
        if response.data:
            log_activity('create', 'form', form_id, f"Form title: {title}")
            flash('Form created successfully.', 'success')
        else:
            print(f"Failed to create form. Response: {response}")
            flash('Failed to create form.', 'danger')
    except Exception as e:
        print(f"Error creating form: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/form/<form_id>')
@login_required
def view_form(form_id):
    # Get form details
    form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
    if not form_response.data:
        flash('Form not found')
        return redirect(url_for('user_dashboard' if not current_user.is_admin else 'admin_dashboard'))
    
    form = form_response.data[0]
    
    # Parse the fields JSON string into Python objects if it's stored as a string
    if isinstance(form['fields'], str):
        try:
            form['fields'] = json.loads(form['fields'])
            print(f"Parsed fields JSON: {form['fields']}")
        except Exception as e:
            print(f"Error parsing form fields: {str(e)}")
            flash(f"Error loading form fields: {str(e)}", 'danger')
            form['fields'] = []
    
    # Add location type identifier for location fields
    if isinstance(form.get('fields'), list):
        for field in form['fields']:
            if isinstance(field, dict) and 'location_field_identifier' in field:
                field['location_type'] = field['location_field_identifier']
            else:
                 # Ensure location_type key exists but is None for non-location fields
                 # This prevents errors in the Jinja template if it checks for the key
                 if isinstance(field, dict):
                     field['location_type'] = None

    # Log the type and content of fields for debugging
    print(f"Form fields type: {type(form['fields'])}")
    print(f"Form fields content after adding location_type: {form['fields']}") # Modified print
    print(f"Number of fields: {len(form['fields']) if isinstance(form['fields'], list) else 'unknown'}")
    
    # Check if user has access (admins always have access)
    if not current_user.is_admin:
        access_response = supabase.table('form_permissions').select('*').eq('form_id', form_id).eq('user_id', current_user.id).execute()
        if not access_response.data:
            flash('You do not have access to this form')
            return redirect(url_for('user_dashboard'))
    
    # Get project details
    project_response = supabase.table('projects').select('*').eq('id', form['project_id']).execute()
    project = project_response.data[0]
    # Remove camp_date if it exists in the fetched data
    project.pop('camp_date', None) 
    
    # Get form submissions (limited to 5 most recent)
    submissions_response = supabase.table('form_submissions').select('*').eq('form_id', form_id).order('created_at', desc=True).limit(5).execute()
    submissions = submissions_response.data
    
    # If admin, get all users for assignment 
    users = []
    user_permissions = []
    if current_user.is_admin:
        # Get all approved users
        users_response = supabase.table('users').select('*').eq('is_approved', True).execute()
        users = users_response.data
        
        # Get users with permissions for this form
        permissions_response = supabase.table('form_permissions').select('*').eq('form_id', form_id).execute()
        permissions = permissions_response.data
        
        # Manually add user data to each permission
        for permission in permissions:
            user_response = supabase.table('users').select('username').eq('id', permission['user_id']).execute()
            if user_response.data:
                permission['users'] = user_response.data[0]
                user_permissions.append(permission)
    
    # Log form view
    log_activity('view', 'form', form_id, f"Form: {form['title']}")
    
    return render_template('view_form.html', 
                          form=form, 
                          project=project, 
                          submissions=submissions, 
                          users=users,
                          user_permissions=user_permissions)

@app.route('/form/<form_id>/grant_access', methods=['POST'])
@login_required
def grant_form_access(form_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No user selected')
        return redirect(url_for('view_form', form_id=form_id))
    
    # Check if permission already exists
    check_response = supabase.table('form_permissions').select('*').eq('form_id', form_id).eq('user_id', user_id).execute()
    if check_response.data:
        flash('User already has access to this form')
        return redirect(url_for('view_form', form_id=form_id))
    
    # Get form title and user name for logging
    form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
    form_title = form_response.data[0]['title'] if form_response.data else "Unknown form"
    
    user_response = supabase.table('users').select('username').eq('id', user_id).execute()
    username = user_response.data[0]['username'] if user_response.data else "Unknown user"
    
    # Add permission
    permission = {
        'id': str(uuid.uuid4()),
        'form_id': form_id,
        'user_id': user_id
    }
    
    supabase.table('form_permissions').insert(permission).execute()
    
    # Log access grant
    log_activity('grant_access', 'form_permission', permission['id'], f"Granted access to {username} for form: {form_title}")
    
    flash('User access granted successfully')
    return redirect(url_for('view_form', form_id=form_id))

@app.route('/form/<form_id>/revoke_access/<permission_id>', methods=['POST'])
@login_required
def revoke_form_access(form_id, permission_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get permission details for logging
    permission_response = supabase.table('form_permissions').select('*').eq('id', permission_id).execute()
    if permission_response.data:
        user_id = permission_response.data[0]['user_id']
        user_response = supabase.table('users').select('username').eq('id', user_id).execute()
        username = user_response.data[0]['username'] if user_response.data else "Unknown user"
        
        form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
        form_title = form_response.data[0]['title'] if form_response.data else "Unknown form"
        
        # Log revoke action
        log_activity('revoke_access', 'form_permission', permission_id, f"Revoked access from {username} for form: {form_title}")
    
    # Delete permission
    supabase.table('form_permissions').delete().eq('id', permission_id).execute()
    flash('User access revoked successfully')
    return redirect(url_for('view_form', form_id=form_id))

@app.route('/form/<form_id>/submit', methods=['POST'])
@login_required
def submit_form(form_id):
    # Get form details
    form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
    if not form_response.data:
        flash('Form not found')
        return redirect(url_for('user_dashboard'))
    
    # Check if user has access (admins always have access)
    if not current_user.is_admin:
        access_response = supabase.table('form_permissions').select('*').eq('form_id', form_id).eq('user_id', current_user.id).execute()
        if not access_response.data:
            flash('You do not have permission to submit this form')
            return redirect(url_for('user_dashboard'))
    
    form = form_response.data[0]
    
    # Parse the fields JSON string into Python objects if it's stored as a string
    if isinstance(form['fields'], str):
        try:
            form['fields'] = json.loads(form['fields'])
            print(f"Parsed fields JSON for form submission: {form['fields']}")
        except Exception as e:
            print(f"Error parsing form fields in submit_form: {str(e)}")
            flash(f"Error processing form: {str(e)}", 'danger')
            return redirect(url_for('view_form', form_id=form_id))
    
    project_response = supabase.table('projects').select('*').eq('id', form['project_id']).execute()
    project = project_response.data[0]
    
    # Generate patient ID using current date
    patient_number = request.form.get('patient_number')
    current_date = datetime.now(EAT).strftime('%d%m%y')
    patient_id = f"{current_date}-{patient_number}"
    
    # Check if patient ID already exists in this project
    # First get all forms for this project
    project_forms_response = supabase.table('forms').select('id').eq('project_id', project['id']).execute()
    if project_forms_response.data:
        project_form_ids = [pform['id'] for pform in project_forms_response.data]
        
        # Check if patient ID exists in any submission for these forms
        existing_submission_query = supabase.table('form_submissions').select('id')
        existing_submission_query = existing_submission_query.in_('form_id', project_form_ids)
        existing_submission_query = existing_submission_query.eq('patient_id', patient_id)
        existing_submission_response = existing_submission_query.execute()
        
        if existing_submission_response.data and len(existing_submission_response.data) > 0:
            flash(f'Patient number {patient_number} already exists in this project. Please use a different number.', 'danger')
            return redirect(url_for('view_form', form_id=form_id))
    
    # Collect form data
    form_data = {}
    for field in form['fields']:
        field_name = field['label'].lower().replace(' ', '_')
        if field['type'] in ['dropdown', 'radio']:
            form_data[field_name] = request.form.get(field_name)
        elif field['type'] == 'checkbox':
            form_data[field_name] = request.form.getlist(field_name)
        else:
            form_data[field_name] = request.form.get(field_name)
    
    # Create submission
    new_submission = {
        'id': str(uuid.uuid4()),
        'form_id': form_id,
        'patient_id': patient_id,
        'submitted_by': current_user.id,
        'data': form_data
    }
    
    supabase.table('form_submissions').insert(new_submission).execute()
    
    # Log form submission
    log_activity('submit', 'form_submission', new_submission['id'], f"Form: {form['title']}, Patient ID: {patient_id}")
    
    flash('Form submitted successfully')
    return redirect(url_for('view_form', form_id=form_id))

@app.route('/form/<form_id>/delete', methods=['POST'])
@login_required
def delete_form(form_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get form details to redirect to project
    form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
    if not form_response.data:
        flash('Form not found')
        return redirect(url_for('admin_dashboard'))
    
    form = form_response.data[0]
    project_id = form['project_id']
    
    try:
        # First delete form permissions
        supabase.table('form_permissions').delete().eq('form_id', form_id).execute()
        
        # Then delete form submissions
        supabase.table('form_submissions').delete().eq('form_id', form_id).execute()
        
        # Log form deletion
        log_activity('delete', 'form', form_id, f"Form title: {form['title']}")
        
        # Finally delete the form
        supabase.table('forms').delete().eq('id', form_id).execute()
        
        flash('Form deleted successfully')
    except Exception as e:
        flash(f'Error deleting form: {str(e)}', 'danger')
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Get approved projects
    response = supabase.table('projects').select('*').execute()
    projects = response.data
    # Remove camp_date from fetched projects
    for p in projects:
        p.pop('camp_date', None)
        
    # Get forms that the user has access to
    accessible_forms = []
    
    # Get permissions for this user
    permissions_response = supabase.table('form_permissions').select('*').eq('user_id', current_user.id).execute()
    
    if permissions_response.data:
        for permission in permissions_response.data:
            # Get form details separately
            form_response = supabase.table('forms').select('*').eq('id', permission['form_id']).execute()
            if form_response.data:
                form = form_response.data[0]
                
                # Parse the fields JSON string into Python objects if needed
                if isinstance(form['fields'], str):
                    try:
                        form['fields'] = json.loads(form['fields'])
                    except Exception as e:
                        print(f"Error parsing form fields in user_dashboard: {str(e)}")
                        form['fields'] = []
                
                # Get the project for this form
                project_response = supabase.table('projects').select('name').eq('id', form['project_id']).execute()
                if project_response.data:
                    form['project_name'] = project_response.data[0]['name']
                    accessible_forms.append(form)
    
    return render_template('user_dashboard.html', projects=projects, accessible_forms=accessible_forms)

@app.route('/dataset')
@login_required
def dataset_view():
    # Get filter parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    field_name = request.args.get('field_name')
    field_value = request.args.get('field_value')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search_term = request.args.get('search', '').strip()  # Get search term
    
    # Log dataset view with filters
    log_details = f"Filters - Project: {project_id or 'All'}, Form: {form_id or 'All'}"
    if field_name and field_value:
        log_details += f", Field: {field_name}={field_value}"
    if start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    if search_term: # Log search term
        log_details += f", Search: '{search_term}'"
    log_activity('view', 'dataset', None, log_details)
    
    print(f"Dataset view called with project_id: {project_id}, form_id: {form_id}, search: {search_term}")
    
    # 1. Fetch Ordered Forms relevant to the filters
    ordered_forms_data = []
    forms_query = supabase.table('forms').select('*')
    if form_id: # If a specific form is selected, only fetch that one
        forms_query = forms_query.eq('id', form_id)
    elif project_id: # If a project is selected, fetch its forms
        forms_query = forms_query.eq('project_id', project_id).order('created_at', desc=False)
    else: # Otherwise fetch all forms, ordered by project then creation
        forms_query = forms_query.order('project_id', desc=False).order('created_at', desc=False)
    
    forms_response = forms_query.execute()
    if forms_response.data:
        ordered_forms_data = forms_response.data

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {} # Stores normalized_label -> original_label mapping

    for form in ordered_forms_data:
        fields_json = form.get('fields', '[]')
        if isinstance(fields_json, str):
            try:
                parsed_fields = json.loads(fields_json)
            except json.JSONDecodeError:
                print(f"Warning: Could not parse fields for form {form.get('id')}")
                parsed_fields = []
        elif isinstance(fields_json, list):
            parsed_fields = fields_json
        else:
            parsed_fields = []

        if isinstance(parsed_fields, list):
             for field in parsed_fields:
                 if isinstance(field, dict) and 'label' in field:
                    label = field['label']
                    # Use same normalization as when accessing data later
                    normalized_label = label.lower().strip().replace(' ', '_') 
                    if normalized_label not in seen_normalized_fields:
                        ordered_fields.append(label)
                        seen_normalized_fields.add(normalized_label)
                        field_label_map[normalized_label] = label

    # 3. Get all submissions based on filters (project or form)
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    if submission_form_ids: # Only query if there are forms to query for
        query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
        query = query.in_('form_id', submission_form_ids) # Filter by the forms we care about
        
        # Apply date filters if present
        if start_date:
            query = query.gte('created_at', start_date)
        if end_date:
            # Add 1 day to end_date to make it inclusive
            try:
                end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
                query = query.lt('created_at', inclusive_end_date) 
            except ValueError:
                 print(f"Invalid end date format: {end_date}")
                 # Optionally handle error, or proceed without end date filter
        
        response = query.execute()
        submissions = response.data
        print(f"Initial submissions fetched: {len(submissions)}")
    else:
        # Handle case where no forms match criteria (e.g., selected project has no forms)
        print(f"No forms found matching filters (Project: {project_id}, Form: {form_id}). No submissions fetched.")
        submissions = []

    # 4. Filter submissions based on search term (if any)
    if search_term:
        filtered_submissions = []
        search_lower = search_term.lower()
        for sub in submissions:
            # Check patient_id first
            if search_lower in str(sub.get('patient_id', '')).lower():
                filtered_submissions.append(sub)
                continue 
            
            # Check submission data values
            if sub.get('data'):
                for value in sub['data'].values():
                    # Handle list values (e.g., from checkboxes)
                    if isinstance(value, list):
                        if any(search_lower in str(item).lower() for item in value):
                            filtered_submissions.append(sub)
                            break 
                    # Handle single values
                    elif search_lower in str(value).lower():
                        filtered_submissions.append(sub)
                        break # Found in this submission, move to next
        submissions = filtered_submissions
        print(f"Found {len(submissions)} submissions after search for '{search_term}'")
    
    # 5. Group submissions by patient_id
    patient_data = {}
    all_data_fields_normalized = set() # Keep track of fields actually in data

    for submission in submissions:
        patient_id = submission['patient_id']
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': []
            }
        patient_data[patient_id]['submissions'].append(submission)
        
        # Collect all unique field keys from actual data
        if submission.get('data'):
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                # Ensure field_label_map has original casing even for data-only fields
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key

    # 6. Apply field value filtering (if specified) AFTER grouping
    if field_name and field_value:
        filtered_patient_data = {}
        normalized_filter_field = field_name.lower().strip().replace(' ', '_')
        filter_value_lower = str(field_value).lower().strip()

        for patient_id, data in patient_data.items():
            found_match = False
            for submission in data['submissions']:
                if submission.get('data'):
                    # Check if the normalized field exists and matches the value
                    if normalized_filter_field in submission['data']:
                        value = submission['data'][normalized_filter_field]
                        # Handle list values (e.g., checkboxes)
                        if isinstance(value, list):
                             if any(filter_value_lower == str(item).lower().strip() for item in value):
                                 found_match = True
                                 break
                        # Handle single values
                        elif str(value).lower().strip() == filter_value_lower:
                            found_match = True
                            break
            if found_match:
                filtered_patient_data[patient_id] = data
        patient_data = filtered_patient_data
        print(f"Found {len(patient_data)} patients after field filtering")

    # 7. Identify Extra Fields (present in data but not in form definitions)
    extra_normalized_fields = all_data_fields_normalized - seen_normalized_fields
    extra_field_labels = sorted([field_label_map[norm_key] for norm_key in extra_normalized_fields if norm_key in field_label_map])
    
    # 8. Combine ordered fields with extra fields
    final_ordered_fields = ordered_fields + extra_field_labels
    
    # 9. Pre-process patient data to merge values using normalized keys
    for patient_id, data in patient_data.items():
        merged_data = {}
        # Keep track of the latest submission date for each field
        last_updated = {} 

        # Sort submissions by date (newest first) to prioritize recent data
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        for submission in sorted_submissions:
            if submission.get('data'):
                submission_date = submission.get('created_at')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    # Only add/update if this submission is newer or the key hasn't been seen
                    if normalized_key not in merged_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                         merged_data[normalized_key] = value
                         if submission_date:
                              last_updated[normalized_key] = submission_date
        data['merged_data'] = merged_data

    # 10. Get data for filter dropdowns
    # Get all projects
    projects_response = supabase.table('projects').select('*').execute()
    all_projects = projects_response.data
    
    # Get forms for filter dropdown (can reuse ordered_forms_data if appropriate or fetch all)
    # Fetching all forms ensures the dropdown is complete even if viewing a specific project's dataset
    all_forms_response = supabase.table('forms').select('*').order('project_id').order('title').execute()
    filter_forms = all_forms_response.data if all_forms_response.data else []

    # Get distinct values for the selected field_name (if any) for the datalist
    # Use the final filtered patient_data for relevance
    field_values = set()
    if field_name:
        normalized_filter_field = field_name.lower().strip().replace(' ', '_')
        for patient_id, data in patient_data.items():
             if normalized_filter_field in data.get('merged_data', {}):
                 value = data['merged_data'][normalized_filter_field]
                 if isinstance(value, list):
                     for item in value:
                         field_values.add(str(item))
                 else:
                    field_values.add(str(value))

    # Convert timestamps in patient data submissions (optional, if needed)
    # for patient_id, data in patient_data.items():
    #     for submission in data['submissions']:
    #         if 'created_at' in submission:
    #             submission['created_at'] = utc_to_eat(submission['created_at']).strftime('%Y-%m-%d %H:%M:%S')

    return render_template('dataset_view.html',
                         patient_data=patient_data,
                         # Pass the final ordered list of field labels
                         ordered_fields=final_ordered_fields, 
                         projects=all_projects,
                         forms=filter_forms, # Use all forms for the filter dropdown
                         field_values=sorted(list(field_values)),
                         selected_project=project_id,
                         selected_form=form_id,
                         selected_field=field_name,
                         selected_value=field_value,
                         start_date=start_date,
                         end_date=end_date,
                         search_term=search_term)

@app.route('/api/submission/<submission_id>')
@login_required
def get_submission(submission_id):
    # Get submission details
    response = supabase.table('form_submissions').select('*, forms(title, fields, projects(name))').eq('id', submission_id).execute()
    if not response.data:
        return jsonify({'error': 'Submission not found'}), 404
    
    submission = response.data[0]
    form = submission['forms']
    
    # Get user details
    user_response = supabase.table('users').select('username').eq('id', submission['submitted_by']).execute()
    user = user_response.data[0]
    
    # Combine data
    result = {
        'Patient ID': submission['patient_id'],
        'Project': form['projects']['name'],
        'Form': form['title'],
        'Submitted By': user['username'],
        'Submission Date': submission['created_at']
    }
    
    # Add form data
    for field in form['fields']:
        result[field['label']] = submission['data'].get(field['label'], '')
    
    return jsonify(result)

@app.route('/api/patient/<patient_id>')
@login_required
def get_patient_data(patient_id):
    try:
        print(f"Fetching data for patient: {patient_id}")
        
        # Get all submissions for this patient
        response = supabase.table('form_submissions').select('*, forms(title, fields, projects(name))').eq('patient_id', patient_id).execute()
        
        if not response.data:
            print(f"No data found for patient {patient_id}")
            return jsonify({'error': 'Patient not found'}), 404
        
        submissions = response.data
        print(f"Number of submissions found: {len(submissions)}")
        
        # Combine all data
        result = {
            'Patient ID': patient_id
        }
        
        # Add data from all submissions
        for submission in submissions:
            form = submission.get('forms', {})
            project = form.get('projects', {})
            
            # Add form submission info
            form_title = form.get('title', 'Unknown Form')
            project_name = project.get('name', 'Unknown Project')
            submission_date = submission.get('created_at', 'Unknown Date')
            
            # Add form data with project and form context
            form_data = submission.get('data', {})
            for key, value in form_data.items():
                result[f"{project_name} - {form_title} - {key}"] = value
            
            # Add submission metadata
            result[f"{project_name} - {form_title} - Submission Date"] = submission_date
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error in get_patient_data: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/export_dataset')
@login_required
def export_dataset():
    # Get filter parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    print(f"Export dataset called with project_id: {project_id}, form_id: {form_id}")
    
    # Log the export action with filter details
    log_details = f"Filters - Project: {project_id or 'All'}, Form: {form_id or 'All'}"
    if start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    log_activity('export', 'dataset', None, log_details)
    
    # Get all submissions with proper project filtering
    if project_id:
        # First get all forms for this project
        forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        if forms_response.data:
            form_ids = [form['id'] for form in forms_response.data]
            print(f"Found {len(form_ids)} forms for project {project_id}")
            
            # Then query submissions for these forms
            query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
            query = query.in_('form_id', form_ids)
            
            if form_id:
                query = query.eq('form_id', form_id)
            if start_date:
                query = query.gte('created_at', start_date)
            if end_date:
                query = query.lte('created_at', end_date)
            
            response = query.execute()
            submissions = response.data
            print(f"Found {len(submissions)} submissions for export")
        else:
            print(f"No forms found for project {project_id}")
            submissions = []
    else:
        # Get all submissions
        query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
        
        if form_id:
            query = query.eq('form_id', form_id)
        if start_date:
            query = query.gte('created_at', start_date)
        if end_date:
            query = query.lte('created_at', end_date)
        
        response = query.execute()
        submissions = response.data
    
    # Group submissions by patient_id
    patient_data = {}
    for submission in submissions:
        patient_id = submission['patient_id']
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': []
            }
        patient_data[patient_id]['submissions'].append(submission)
    
    # Get all unique field names across all forms
    all_fields = set()
    for submission in submissions:
        form = submission.get('forms', {})
        if form and 'fields' in form:
            for field in form['fields']:
                normalized_field = field['label'].lower().strip()
                all_fields.add(normalized_field)
        if 'data' in submission:
            for field in submission['data'].keys():
                normalized_field = field.lower().strip()
                all_fields.add(normalized_field)
    
    all_fields = sorted([field.title() for field in all_fields])
    
    # Create DataFrame
    data = []
    for patient_id, data_dict in patient_data.items():
        row = {'Patient ID': patient_id}
        for submission in data_dict['submissions']:
            if 'data' in submission:
                form = submission.get('forms', {})
                project = form.get('projects', {})
                form_title = form.get('title', 'Unknown Form')
                project_name = project.get('name', 'Unknown Project')
                
                # Add context to fields
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip()
                    # Include project and form name for clarity
                    row[f"{project_name} - {form_title} - {normalized_key.title()}"] = value
                
                # Add submission date (convert to EAT timezone)
                submission_date = submission.get('created_at', '')
                if submission_date:
                    submission_date = utc_to_eat(submission_date).strftime('%Y-%m-%d %H:%M:%S')
                row[f"{project_name} - {form_title} - Submission Date"] = submission_date
        data.append(row)
    
    df = pd.DataFrame(data)
    
    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Dataset', index=False)
        
        # Auto-adjust columns' width
        worksheet = writer.sheets['Dataset']
        for i, col in enumerate(df.columns):
            max_length = max(df[col].astype(str).apply(len).max(), len(col)) + 2
            worksheet.set_column(i, i, max_length)
    
    output.seek(0)
    
    # Generate a filename based on the filters
    filename = 'dataset'
    if project_id:
        # Get project name for filename
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            project_name = project_response.data[0]['name']
            filename = f"{project_name}_dataset"
    
    if form_id:
        # Get form name for filename
        form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
        if form_response.data:
            form_title = form_response.data[0]['title']
            filename = f"{filename}_{form_title}"
    
    if start_date or end_date:
        date_range = f"_{start_date or 'start'}_to_{end_date or 'end'}"
        filename = f"{filename}{date_range}"
    
    filename = f"{filename}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@app.route('/stream/submissions')
@login_required
def stream_submissions():
    def generate():
        # Get the last submission ID
        last_submission = supabase.table('form_submissions').select('id').order('created_at', desc=True).limit(1).execute()
        last_id = last_submission.data[0]['id'] if last_submission.data else None
        
        while True:
            # Check for new submissions
            new_submissions = supabase.table('form_submissions').select('*, forms(title, fields, projects(name))').gt('id', last_id).execute()
            
            if new_submissions.data:
                for submission in new_submissions.data:
                    # Format the submission data
                    data = {
                        'patient_id': submission['patient_id'],
                        'form_title': submission['forms']['title'],
                        'project_name': submission['forms']['projects']['name'],
                        'submission_data': submission['data'],
                        'created_at': submission['created_at']
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                    last_id = submission['id']
            
            # Sleep for a short time before checking again
            time.sleep(1)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/projects')
@login_required
def projects():
    try:
        # Query all projects, ordering by creation date
        response = supabase.table('projects').select('*').order('created_at', desc=True).execute()
        projects = response.data if response.data else []
        
        # Check if this is being accessed from dataset view
        is_dataset_view = request.args.get('dataset_view', 'false').lower() in ['true', '1', 'yes']
        
        return render_template('projects_list.html', 
                             projects=projects,
                             is_dataset_view=is_dataset_view)
    except Exception as e:
        flash(f"Error fetching projects: {str(e)}", 'error')
        return redirect(url_for('admin_dashboard' if current_user.is_admin else 'user_dashboard'))

def utc_to_eat(utc_timestamp):
    """Convert UTC timestamp string to EAT (GMT+3) timezone"""
    if not utc_timestamp:
        return None
    
    try:
        # If the timestamp is already a datetime object
        if isinstance(utc_timestamp, datetime):
            if utc_timestamp.tzinfo is None:  # Naive datetime, assume UTC
                utc_dt = utc_timestamp.replace(tzinfo=timezone.utc)
            else:  # Already tz-aware
                utc_dt = utc_timestamp
        else:  # String timestamp
            # Handle both formats: with or without timezone info
            try:
                utc_dt = datetime.fromisoformat(utc_timestamp.replace('Z', '+00:00'))
            except ValueError:
                # If format is different, try parsing as UTC
                utc_dt = datetime.strptime(utc_timestamp, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        
        # Convert to EAT
        eat_dt = utc_dt.astimezone(EAT)
        return eat_dt
    except Exception as e:
        print(f"Error converting timestamp: {str(e)}")
        return utc_timestamp  # Return original if conversion fails

@app.route('/admin/activity-logs')
@login_required
def activity_logs():
    # Ensure user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('index'))
    
    # Get page number for pagination (default to 1)
    page = request.args.get('page', 1, type=int)
    limit = 20
    offset = (page - 1) * limit
    
    # Get count of all logs for pagination
    count_response = supabase.table('log_activities').select('id', count='exact').execute()
    total_logs = count_response.count if hasattr(count_response, 'count') else 0
    
    # Get logs with pagination
    response = supabase.table('log_activities').select('*').order('created_at', desc=True).range(offset, offset + limit - 1).execute()
    logs = response.data
    
    # Convert timestamps to EAT timezone
    for log in logs:
        if 'created_at' in log:
            log['created_at_original'] = log['created_at']  # Keep original for reference
            log['created_at'] = utc_to_eat(log['created_at']).strftime('%Y-%m-%d %H:%M:%S')
    
    # Calculate total pages
    total_pages = (total_logs + limit - 1) // limit
    
    # Log this view action
    log_activity('view', 'activity_logs')
    
    return render_template('activity_logs.html', 
                          logs=logs, 
                          current_page=page, 
                          total_pages=total_pages)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'on'
    
    # Check if username exists
    response = supabase.table('users').select('*').eq('username', username).execute()
    if response.data:
        flash('Username already exists', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Create new user
    hashed_password = generate_password_hash(password)
    new_user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'password': hashed_password,
        'is_admin': is_admin,
        'is_approved': True  # Auto-approve users created by admin
    }
    
    supabase.table('users').insert(new_user).execute()
    
    # Log user creation
    log_activity('create', 'user', new_user['id'], f"Created user: {username}, Admin: {is_admin}")
    
    flash('User created successfully', 'success')
    return redirect(url_for('admin_dashboard'))

def fig_to_base64(fig):
    """Convert a matplotlib figure to base64 encoded string for HTML display"""
    buf = BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=150)
    buf.seek(0)
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)  # Close figure to free memory
    return img_str

def clean_field_name(name):
    """Clean field names for better display"""
    if isinstance(name, str):
        # Remove any project or form prefixes
        if ' - ' in name:
            name = name.split(' - ')[-1]
        # Convert underscores to spaces and capitalize
        return name.replace('_', ' ').title()
    return name

def prepare_dataset_for_analysis(project_id=None, form_id=None, start_date=None, end_date=None):
    """Prepare dataset for visualization and analysis"""
    # This is similar to the dataset_view logic but optimized for analytics
    if project_id:
        # First get all forms for this project
        forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        if forms_response.data:
            form_ids = [form['id'] for form in forms_response.data]
            
            # Then query submissions for these forms
            query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
            query = query.in_('form_id', form_ids)
            
            if form_id:
                query = query.eq('form_id', form_id)
            if start_date:
                query = query.gte('created_at', start_date)
            if end_date:
                query = query.lte('created_at', end_date)
            
            response = query.execute()
            submissions = response.data
        else:
            submissions = []
    else:
        # Get all submissions
        query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
        
        if form_id:
            query = query.eq('form_id', form_id)
        if start_date:
            query = query.gte('created_at', start_date)
        if end_date:
            query = query.lte('created_at', end_date)
        
        response = query.execute()
        submissions = response.data
    
    # Create a flat dataframe with all submissions
    data = []
    for submission in submissions:
        row = {
            'patient_id': submission['patient_id'],
            'submission_id': submission['id'],
            'created_at': utc_to_eat(submission['created_at']).strftime('%Y-%m-%d %H:%M:%S') if submission.get('created_at') else '',
        }
        
        # Get form and project info
        form = submission.get('forms', {})
        if form:
            form_title = form.get('title', 'Unknown Form')
            project = form.get('projects', {})
            project_name = project.get('name', 'Unknown Project') if project else 'Unknown Project'
            
            row['form_title'] = form_title
            row['project_name'] = project_name
            
            # Add form data with proper context
            if submission.get('data'):
                for key, value in submission['data'].items():
                    # Check if it's a multi-value field (like checkboxes)
                    if isinstance(value, list):
                        # Store as comma-separated string
                        value = ', '.join(str(v) for v in value)
                    
                    # Store the field with project and form context
                    field_key = f"{project_name} - {form_title} - {key}"
                    row[field_key] = value
        
        data.append(row)
    
    # Convert to dataframe
    df = pd.DataFrame(data)
    return df

def get_summary_statistics(data, field_name):
    """Generate comprehensive summary statistics for numerical data"""
    if data.empty or field_name not in data.columns:
        return None
    
    # Try to convert to numeric regardless of current type
    numeric_data = pd.to_numeric(data[field_name], errors='coerce').dropna()
    
    if len(numeric_data) == 0:
        return None
        
    # Calculate basic statistics
    stats = {
        'Count': len(numeric_data),
        'Missing': len(data) - len(numeric_data),
        'Mean': numeric_data.mean(),
        'Median': numeric_data.median(),
        'Mode': numeric_data.mode().iloc[0] if not numeric_data.mode().empty else None,
        'Std Dev': numeric_data.std(),
        'Variance': numeric_data.var(),
        'Min': numeric_data.min(),
        'Max': numeric_data.max(),
        'Range': numeric_data.max() - numeric_data.min(),
        '25th Percentile': numeric_data.quantile(0.25),
        '50th Percentile': numeric_data.quantile(0.5),
        '75th Percentile': numeric_data.quantile(0.75),
        'IQR': numeric_data.quantile(0.75) - numeric_data.quantile(0.25),
        'Skewness': numeric_data.skew(),
        'Kurtosis': numeric_data.kurtosis()
    }
    
    # Convert to dataframe for display
    stats_df = pd.DataFrame(list(stats.items()), columns=['Statistic', 'Value'])
    
    # Format numbers for better display
    stats_df['Value'] = stats_df['Value'].apply(lambda x: f"{x:.4f}" if isinstance(x, float) else x)
    
    return stats_df.to_html(classes='table table-striped table-hover', index=False)

@app.route('/admin/analytics', methods=['GET', 'POST'])
@login_required
def analytics():
    if not current_user.is_admin:
        flash('You do not have permission to access analytics.', 'danger')
        return redirect(url_for('index'))
    
    # Get filter parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    analysis_type = request.args.get('analysis_type')
    field1 = request.args.get('field1')
    field2 = request.args.get('field2')
    
    # Get correlation fields (multiple selection)
    correlation_fields = request.args.getlist('correlation_fields[]')
    
    # Get all projects for filter dropdown
    projects_response = supabase.table('projects').select('*').execute()
    all_projects = projects_response.data
    
    # Get relevant forms based on project selection
    if project_id:
        # Only get forms for the selected project
        forms_response = supabase.table('forms').select('*').eq('project_id', project_id).execute()
        forms = forms_response.data
    else:
        # Get all forms if no project is selected
        forms_response = supabase.table('forms').select('*').execute()
        forms = forms_response.data
    
    # Initialize variables
    df = None
    all_fields = []
    field_types = {}
    plots = []
    stats = None
    title = None
    
    # Only proceed with analysis if there are filter parameters
    if project_id or form_id:
        # Prepare dataset
        df = prepare_dataset_for_analysis(project_id, form_id, start_date, end_date)
        
        # If dataframe is empty, show message
        if df.empty:
            flash('No data available for the selected filters.', 'warning')
        else:
            # Get all field names for dropdowns
            excluded_cols = ['patient_id', 'submission_id', 'created_at', 'form_title', 'project_name']
            all_fields = [col for col in df.columns if col not in excluded_cols]
            
            # Attempt to convert potentially numeric columns to numeric type
            for field in all_fields:
                if df[field].dtype == 'object':  # If it's a string/object type
                    # Try to convert to numeric, setting errors='coerce' will convert failures to NaN
                    numeric_series = pd.to_numeric(df[field], errors='coerce')
                    # If the conversion didn't result in all NaNs, we can consider it numeric
                    if not numeric_series.isna().all():
                        # Calculate what percentage of values converted successfully
                        success_rate = 1 - (numeric_series.isna().sum() / len(numeric_series))
                        # If more than 80% of values converted successfully, treat as numeric
                        if success_rate > 0.8:
                            df[field] = numeric_series
            
            # Determine field types for analysis
            for field in all_fields:
                if df[field].dtype == 'object':  # String/categorical
                    # Count unique values to determine if it's categorical
                    unique_count = df[field].nunique()
                    if unique_count <= 15:  # Arbitrary threshold for categorical
                        field_types[field] = 'categorical'
                    else:
                        field_types[field] = 'text'
                elif np.issubdtype(df[field].dtype, np.number):  # Numeric
                    field_types[field] = 'numeric'
                else:
                    field_types[field] = 'unknown'
            
            # If analysis fields are specified, perform analysis
            if analysis_type:
                # 1. Summary Statistics
                if analysis_type == 'summary_statistics' and field1:
                    title = f'Summary Statistics for {clean_field_name(field1)}'
                    
                    # Try to convert the field to numeric regardless of its detected type
                    # This handles cases where a numeric field might be stored as strings
                    numeric_data = pd.to_numeric(df[field1], errors='coerce').dropna()
                    
                    if len(numeric_data) > 0:  # If we have any numeric values
                        # Calculate key statistics
                        key_stats = {
                            'Count': len(numeric_data),
                            'Missing Values': len(df) - len(numeric_data),
                            'Mean': numeric_data.mean(),
                            'Standard Deviation': numeric_data.std(),
                            'Median': numeric_data.median(),
                            'Minimum': numeric_data.min(),
                            'Maximum': numeric_data.max(),
                            'Range': numeric_data.max() - numeric_data.min(),
                            '25th Percentile': numeric_data.quantile(0.25),
                            '75th Percentile': numeric_data.quantile(0.75)
                        }
                        
                        # Convert to DataFrame for display
                        stats_df = pd.DataFrame(list(key_stats.items()), columns=['Statistic', 'Value'])
                        
                        # Format numbers for better display
                        stats_df['Value'] = stats_df['Value'].apply(lambda x: f"{x:.4f}" if isinstance(x, float) else x)
                        
                        # Display statistics
                        stats = stats_df.to_html(classes='table table-striped table-hover table-bordered', index=False)
                        
                        # Histogram with mean and median lines
                        fig, ax = plt.subplots(figsize=(12, 6))
                        sns.histplot(numeric_data, kde=True, ax=ax)
                        
                        # Add vertical lines for mean and median
                        plt.axvline(numeric_data.mean(), color='red', linestyle='dashed', linewidth=1, label=f'Mean: {numeric_data.mean():.2f}')
                        plt.axvline(numeric_data.median(), color='green', linestyle='dashed', linewidth=1, label=f'Median: {numeric_data.median():.2f}')
                        
                        # Add standard deviation range
                        mean = numeric_data.mean()
                        std = numeric_data.std()
                        plt.axvline(mean + std, color='orange', linestyle='dotted', linewidth=1, label=f'Mean + SD: {mean + std:.2f}')
                        plt.axvline(mean - std, color='orange', linestyle='dotted', linewidth=1, label=f'Mean - SD: {mean - std:.2f}')
                        
                        ax.set_title(f'Distribution of {clean_field_name(field1)}')
                        ax.set_xlabel(clean_field_name(field1))
                        ax.set_ylabel('Frequency')
                        plt.legend()
                        plt.tight_layout()
                        plots.append({
                            'title': 'Histogram with Mean and Median',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Boxplot
                        fig, ax = plt.subplots(figsize=(12, 6))
                        sns.boxplot(x=numeric_data, ax=ax)
                        ax.set_title(f'Boxplot of {clean_field_name(field1)}')
                        ax.set_xlabel(clean_field_name(field1))
                        plt.tight_layout()
                        plots.append({
                            'title': 'Boxplot',
                            'img': fig_to_base64(fig)
                        })
                        
                        # QQ Plot
                        from scipy import stats as scipy_stats
                        fig, ax = plt.subplots(figsize=(12, 6))
                        scipy_stats.probplot(numeric_data, plot=ax)
                        ax.set_title(f'Q-Q Plot of {clean_field_name(field1)} (Normality Check)')
                        plt.tight_layout()
                        plots.append({
                            'title': 'Q-Q Plot',
                            'img': fig_to_base64(fig)
                        })
                        
                    else:
                        non_numeric_values = df[field1].dropna().head(5).tolist()
                        example_values = ', '.join([f'"{str(v)}"' for v in non_numeric_values])
                        stats = f"""<div class='alert alert-warning'>
                            <p>Unable to perform numeric analysis on this field. The values don't appear to be numeric.</p>
                            <p>Examples of values in this field: {example_values}</p>
                            <p>Please ensure the field contains numeric data or select a different field.</p>
                        </div>"""
                
                # 2. Frequency Distribution
                elif analysis_type == 'frequency' and field1:
                    field1_label = field1.split(' - ')[-1] if ' - ' in field1 else field1
                    title = f'Frequency Distribution of {field1_label}'
                    
                    if field_types[field1] == 'categorical':
                        # Count frequency and sort
                        freq = df[field1].value_counts().reset_index()
                        freq.columns = ['Value', 'Count']
                        freq = freq.sort_values('Count', ascending=False)
                        
                        # Create table stats
                        stats = freq.to_html(classes='table table-striped table-hover', index=False)
                        
                        # Bar chart
                        fig, ax = plt.subplots(figsize=(10, 6))
                        sns.barplot(x='Value', y='Count', data=freq, ax=ax)
                        ax.set_title(title)
                        ax.set_xlabel(field1_label)
                        ax.set_ylabel('Frequency')
                        plt.xticks(rotation=45, ha='right')
                        plt.tight_layout()
                        plots.append({
                            'title': 'Bar Chart - Frequency Distribution',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Pie chart if fewer than 10 categories
                        if len(freq) <= 10:
                            fig, ax = plt.subplots(figsize=(10, 6))
                            plt.pie(freq['Count'], labels=freq['Value'], autopct='%1.1f%%')
                            plt.title(f'Pie Chart - {title}')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Pie Chart - Distribution',
                                'img': fig_to_base64(fig)
                            })
                    
                    elif field_types[field1] == 'numeric':
                        # Convert to numeric
                        df[field1] = pd.to_numeric(df[field1], errors='coerce')
                        
                        # Get comprehensive summary statistics
                        stats = get_summary_statistics(df, field1)
                        
                        # Histogram
                        fig, ax = plt.subplots(figsize=(10, 6))
                        sns.histplot(df[field1].dropna(), kde=True, ax=ax)
                        ax.set_title(f'Histogram - {title}')
                        ax.set_xlabel(field1_label)
                        ax.set_ylabel('Frequency')
                        plt.tight_layout()
                        plots.append({
                            'title': 'Histogram',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Boxplot
                        fig, ax = plt.subplots(figsize=(10, 6))
                        sns.boxplot(x=df[field1].dropna(), ax=ax)
                        ax.set_title(f'Boxplot - {title}')
                        ax.set_xlabel(field1_label)
                        plt.tight_layout()
                        plots.append({
                            'title': 'Boxplot',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Use simpler statistics for frequency distribution
                        desc_stats = df[field1].describe().reset_index()
                        desc_stats.columns = ['Statistic', 'Value']
                        stats = desc_stats.to_html(classes='table table-striped table-hover', index=False)
                    
                    else:  # Text data
                        # Just show frequency
                        freq = df[field1].value_counts().head(20).reset_index()
                        freq.columns = ['Value', 'Count']
                        stats = freq.to_html(classes='table table-striped table-hover', index=False)

                # 3. Cross-tabulation
                elif analysis_type == 'crosstab' and field1 and field2:
                    title = f'Relationship between {clean_field_name(field1)} and {clean_field_name(field2)}'
                    
                    # Extract just the variable names (without project and form prefixes)
                    field1_label = field1.split(' - ')[-1] if ' - ' in field1 else field1
                    field2_label = field2.split(' - ')[-1] if ' - ' in field2 else field2
                    title = f'Relationship between {field1_label} and {field2_label}'
                    
                    # Check if both fields exist in the dataset
                    if field1 not in df.columns or field2 not in df.columns:
                        stats = f"<div class='alert alert-warning'>One or both selected fields do not exist in the dataset.</div>"
                    else:
                        # Check field types and handle appropriately
                        field1_type = field_types.get(field1, 'unknown')
                        field2_type = field_types.get(field2, 'unknown')
                        
                        # Cross-tab for categorical vs categorical
                        if field1_type == 'categorical' and field2_type == 'categorical':
                            # Create cross-tabulation
                            ct = pd.crosstab(df[field1], df[field2])
                            stats = ct.to_html(classes='table table-striped table-hover')
                            
                            # Heatmap
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.heatmap(ct, annot=True, fmt='d', cmap='YlGnBu', ax=ax)
                            ax.set_title(f'Heatmap - {title}')
                            ax.set_xlabel(field2_label)
                            ax.set_ylabel(field1_label)
                            plt.tight_layout()
                            plots.append({
                                'title': 'Heatmap - Cross-tabulation',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Stacked bar chart
                            fig, ax = plt.subplots(figsize=(12, 8))
                            ct_pct = ct.div(ct.sum(axis=1), axis=0)
                            ct_pct.plot(kind='bar', stacked=True, ax=ax)
                            ax.set_title(f'Stacked Bar Chart - {title}')
                            ax.set_xlabel(field1_label)
                            ax.set_ylabel('Proportion')
                            ax.legend(title=field2_label)
                            plt.tight_layout()
                            plots.append({
                                'title': 'Stacked Bar Chart',
                                'img': fig_to_base64(fig)
                            })
                        
                        # Categorical vs Numeric
                        elif field1_type == 'categorical' and field2_type == 'numeric':
                            # Convert to numeric if needed
                            df[field2] = pd.to_numeric(df[field2], errors='coerce')
                            
                            # Boxplot by group
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.boxplot(x=field1, y=field2, data=df, ax=ax)
                            ax.set_title(f'Boxplot - {title}')
                            ax.set_xlabel(field1_label)
                            ax.set_ylabel(field2_label)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Boxplot by Group',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Group statistics
                            grouped_stats = df.groupby(field1)[field2].describe().reset_index()
                            stats = grouped_stats.to_html(classes='table table-striped table-hover')
                            
                            # Bar chart with error bars
                            fig, ax = plt.subplots(figsize=(12, 8))
                            group_means = df.groupby(field1)[field2].mean().reset_index()
                            group_std = df.groupby(field1)[field2].std().reset_index()[field2]
                            sns.barplot(x=field1, y=field2, data=group_means, ax=ax, yerr=group_std)
                            ax.set_title(f'Mean {field2_label} by {field1_label}')
                            ax.set_xlabel(field1_label)
                            ax.set_ylabel(f'Mean {field2_label}')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Mean Values by Group',
                                'img': fig_to_base64(fig)
                            })
                        
                        # Numeric vs Categorical (flip the variables)
                        elif field1_type == 'numeric' and field2_type == 'categorical':
                            # Convert to numeric if needed
                            df[field1] = pd.to_numeric(df[field1], errors='coerce')
                            
                            # Boxplot by group
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.boxplot(x=field2, y=field1, data=df, ax=ax)
                            ax.set_title(f'Boxplot - {title}')
                            ax.set_xlabel(field2_label)
                            ax.set_ylabel(field1_label)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Boxplot by Group',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Group statistics
                            grouped_stats = df.groupby(field2)[field1].describe().reset_index()
                            stats = grouped_stats.to_html(classes='table table-striped table-hover')
                        
                        # Numeric vs Numeric
                        elif field1_type == 'numeric' and field2_type == 'numeric':
                            # Convert to numeric
                            df[field1] = pd.to_numeric(df[field1], errors='coerce')
                            df[field2] = pd.to_numeric(df[field2], errors='coerce')
                            
                            # Drop rows with missing values in either field
                            valid_data = df.dropna(subset=[field1, field2])
                            
                            if len(valid_data) < 2:
                                stats = "<div class='alert alert-warning'>Not enough valid data points for analysis.</div>"
                            else:
                                # Scatter plot
                                fig, ax = plt.subplots(figsize=(10, 6))
                                sns.scatterplot(x=field1, y=field2, data=valid_data, ax=ax)
                                ax.set_title(f'Scatter Plot - {title}')
                                ax.set_xlabel(field1_label)
                                ax.set_ylabel(field2_label)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Scatter Plot',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Calculate correlation and show simple statistics
                                corr = valid_data[[field1, field2]].corr().iloc[0, 1]
                                
                                stats = f"""
                                <table class="table table-striped table-hover">
                                    <thead>
                                        <tr>
                                            <th>Statistic</th>
                                            <th>Value</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>Correlation</td>
                                            <td>{corr:.4f}</td>
                                        </tr>
                                        <tr>
                                            <td>Sample Size</td>
                                            <td>{len(valid_data)}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                """
                                
                                # Regression plot
                                fig, ax = plt.subplots(figsize=(10, 6))
                                sns.regplot(x=field1, y=field2, data=valid_data, ax=ax)
                                ax.set_title(f'Regression Plot - {title}')
                                ax.set_xlabel(field1_label)
                                ax.set_ylabel(field2_label)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Regression Plot',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Joint plot (combines scatter and histograms)
                                g = sns.jointplot(x=field1, y=field2, data=valid_data, kind="reg", height=8)
                                g.fig.suptitle(f'Joint Plot - {title}', y=1.05)
                                g.set_axis_labels(field1_label, field2_label)
                                plots.append({
                                    'title': 'Joint Plot',
                                    'img': fig_to_base64(g.fig)
                                })
                        
                        else:
                            stats = "<div class='alert alert-warning'>Cannot perform cross-tabulation on these field types.</div>"
                
                # 4. Time Series Analysis
                elif analysis_type == 'timeseries' and field1:
                    field1_label = field1.split(' - ')[-1] if ' - ' in field1 else field1
                    title = f'Time Series Analysis of {field1_label}'
                    
                    # Convert created_at to datetime
                    if 'created_at' in df.columns:
                        df['date'] = pd.to_datetime(df['created_at']).dt.date
                        
                        if field_types[field1] == 'numeric':
                            # Convert to numeric if needed
                            df[field1] = pd.to_numeric(df[field1], errors='coerce')
                            
                            # Group by date and calculate mean
                            time_data = df.groupby('date')[field1].mean().reset_index()
                            time_data = time_data.sort_values('date')
                            
                            # Line plot
                            fig, ax = plt.subplots(figsize=(12, 6))
                            sns.lineplot(x='date', y=field1, data=time_data, marker='o', ax=ax)
                            ax.set_title(f'Time Series - Average {field1_label} Over Time')
                            ax.set_xlabel('Date')
                            ax.set_ylabel(f'Average {field1_label}')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Time Series Plot',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Output detailed statistics
                            stats_html = [
                                f"<h5>Overall Summary Statistics for {field1_label}</h5>",
                                get_summary_statistics(df, field1)
                            ]
                            
                            # Group by date and get detailed stats
                            daily_stats = []
                            for date, group_df in df.groupby('date'):
                                group_data = group_df[field1].describe().reset_index()
                                group_data.columns = ['Statistic', 'Value']
                                daily_stats.append(f"<h5>Statistics for {date}</h5>")
                                daily_stats.append(group_data.to_html(classes='table table-striped table-hover', index=False))
                            
                            # Combine stats
                            if daily_stats:
                                stats_html.extend([
                                    "<h4>Daily Statistics</h4>",
                                    *daily_stats
                                ])
                            
                            stats = "<div>" + "".join(stats_html) + "</div>"
                            
                        elif field_types[field1] == 'categorical':
                            # Group by date and category, get counts
                            time_data = df.groupby(['date', field1]).size().reset_index(name='count')
                            
                            # Pivot to get categories as columns
                            pivot_data = time_data.pivot(index='date', columns=field1, values='count').fillna(0)
                            
                            # Stacked area plot
                            fig, ax = plt.subplots(figsize=(12, 6))
                            pivot_data.plot(kind='area', stacked=True, ax=ax)
                            ax.set_title(f'Time Series - {field1_label} Distribution Over Time')
                            ax.set_xlabel('Date')
                            ax.set_ylabel('Count')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Stacked Area Plot',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Line plot for each category
                            fig, ax = plt.subplots(figsize=(12, 6))
                            for category in pivot_data.columns:
                                pivot_data[category].plot(ax=ax, marker='o', label=category)
                            ax.set_title(f'Time Series - {field1_label} by Category Over Time')
                            ax.set_xlabel('Date')
                            ax.set_ylabel('Count')
                            plt.legend(title=field1_label)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Time Series by Category',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Output the stacked data in a table
                            stats = pivot_data.reset_index().to_html(classes='table table-striped table-hover')
                    
                    else:
                        stats = "<div class='alert alert-warning'>No time data available for time series analysis.</div>"

                # 5. Correlation Matrix
                elif analysis_type == 'correlation':
                    title = 'Correlation Matrix Analysis'
                    
                    # Use selected fields if provided, otherwise use all numeric fields
                    if correlation_fields and len(correlation_fields) >= 2:
                        selected_numeric_fields = correlation_fields
                        title = f'Correlation Matrix Analysis for Selected Fields ({len(selected_numeric_fields)} fields)'
                    else:
                        # First identify fields that are explicitly marked as numeric
                        numeric_fields = [field for field in all_fields if field_types.get(field) == 'numeric']
                        
                        # Then try to convert other fields to numeric that aren't marked as numeric
                        potential_numeric_fields = []
                        for field in all_fields:
                            if field not in numeric_fields and field != 'created_at' and field != 'patient_id' and field != 'id':
                                # Try to convert to numeric and check if it works
                                try:
                                    pd.to_numeric(df[field], errors='raise')
                                    potential_numeric_fields.append(field)
                                except:
                                    pass
                        
                        # Combine both lists
                        selected_numeric_fields = numeric_fields + potential_numeric_fields
                    
                    if len(selected_numeric_fields) < 2:
                        stats = "<div class='alert alert-warning'>Not enough numeric fields available for correlation analysis. Please ensure at least 2 numeric fields are present in the dataset.</div>"
                    else:
                        # Create a correlation matrix with selected numeric fields
                        # Convert fields to numeric before correlation
                        numeric_df = df[selected_numeric_fields].apply(pd.to_numeric, errors='coerce')
                        corr_matrix = numeric_df.corr().round(3)
                        
                        # Generate a heatmap visualization
                        plt.figure(figsize=(max(8, len(selected_numeric_fields) * 0.8), max(6, len(selected_numeric_fields) * 0.8)))
                        mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
                        
                        # Generate heatmap with correlation values
                        fig, ax = plt.subplots(figsize=(max(10, len(selected_numeric_fields)), max(8, len(selected_numeric_fields))))
                        cmap = sns.diverging_palette(230, 20, as_cmap=True)
                        sns.heatmap(
                            corr_matrix, 
                            mask=mask, 
                            cmap=cmap, 
                            vmax=1, 
                            vmin=-1, 
                            center=0,
                            annot=True, 
                            fmt=".2f",
                            square=True, 
                            linewidths=.5, 
                            cbar_kws={"shrink": .8}
                        )
                        
                        # Extract just the variable names (without project and form prefixes)
                        clean_labels = []
                        for field in selected_numeric_fields:
                            # Split by hyphen and get the last part which should be the variable name
                            if ' - ' in field:
                                parts = field.split(' - ')
                                clean_labels.append(parts[-1])  # Get only the last part (variable name)
                            else:
                                clean_labels.append(field)
                        
                        # Use clean labels for visualization
                        ax.set_xticklabels(clean_labels, rotation=45, ha='right')
                        ax.set_yticklabels(clean_labels, rotation=0)
                        
                        plt.title('Correlation Matrix Heatmap')
                        plt.tight_layout()
                        plots.append({
                            'title': 'Correlation Matrix Heatmap',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Create a clean correlation matrix with variable names only for display
                        clean_corr_matrix = corr_matrix.copy()
                        clean_corr_matrix.index = clean_labels
                        clean_corr_matrix.columns = clean_labels
                        
                        # Create an HTML table of the correlation matrix
                        corr_html = clean_corr_matrix.to_html(classes='table table-striped table-hover table-bordered')
                        
                        # Highlight strong correlations with color coding
                        def highlight_correlations(corr_html):
                            import re
                            # Replace positive correlations
                            for i in range(1, 10):
                                val = i / 10
                                corr_html = re.sub(
                                    r'>0\.{}[0-9]<'.format(i),
                                    ' style="background-color:rgba(0,100,0,0.{})">{}<'.format(i+1, '>0.{}[0-9]<'.format(i)),
                                    corr_html
                                )
                            # Replace negative correlations
                            for i in range(1, 10):
                                val = i / 10
                                corr_html = re.sub(
                                    r'>-0\.{}[0-9]<'.format(i),
                                    ' style="background-color:rgba(100,0,0,0.{})">{}<'.format(i+1, '>-0.{}[0-9]<'.format(i)),
                                    corr_html
                                )
                            return corr_html
                        
                        # Add correlation interpretation guide
                        stats = f"""
                        <div class="mb-4">
                            <h5>Correlation Matrix</h5>
                            <p>This matrix shows the Pearson correlation coefficient between pairs of numeric variables. 
                               Values range from -1 (perfect negative correlation) to 1 (perfect positive correlation). 
                               A value of 0 indicates no linear correlation.</p>
                            <div class="table-responsive">
                                {corr_html}
                            </div>
                        </div>
                        <div class="mb-4">
                            <h5>Interpretation Guide</h5>
                            <ul>
                                <li><strong>0.8 to 1.0 (or -0.8 to -1.0):</strong> Very strong positive (or negative) correlation</li>
                                <li><strong>0.6 to 0.8 (or -0.6 to -0.8):</strong> Strong positive (or negative) correlation</li>
                                <li><strong>0.4 to 0.6 (or -0.4 to -0.6):</strong> Moderate positive (or negative) correlation</li>
                                <li><strong>0.2 to 0.4 (or -0.2 to -0.4):</strong> Weak positive (or negative) correlation</li>
                                <li><strong>0.0 to 0.2 (or 0.0 to -0.2):</strong> Very weak or no correlation</li>
                            </ul>
                        </div>
                        """
                
                # 6. Cohort Analysis
                elif analysis_type == 'cohort' and field1:
                    field1_label = field1.split(' - ')[-1] if ' - ' in field1 else field1
                    title = f'Cohort Analysis by {field1_label}'
                    
                    if 'created_at' not in df.columns:
                        stats = "<div class='alert alert-warning'>No time data available for cohort analysis.</div>"
                    else:
                        # Create cohorts based on the selected field
                        if field_types[field1] == 'categorical':
                            # Extract month from created_at
                            df['cohort_month'] = pd.to_datetime(df['created_at']).dt.to_period('M')
                            
                            # Count submissions per cohort and month
                            cohort_data = (
                                df.groupby(['cohort_month', field1])
                                .size()
                                .reset_index(name='count')
                            )
                            
                            # Create pivot table of cohorts
                            cohort_pivot = cohort_data.pivot_table(
                                index='cohort_month', 
                                columns=field1, 
                                values='count', 
                                aggfunc='sum'
                            ).fillna(0)
                            
                            # Visualization: Stacked bar chart of cohorts
                            fig, ax = plt.subplots(figsize=(12, 8))
                            cohort_pivot.plot(kind='bar', stacked=True, ax=ax)
                            ax.set_title(f'Monthly Cohorts by {field1_label}')
                            ax.set_xlabel('Month')
                            ax.set_ylabel('Number of Submissions')
                            plt.legend(title=field1_label)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Monthly Cohort Analysis',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Calculate proportion of each cohort
                            cohort_pct = cohort_pivot.div(cohort_pivot.sum(axis=1), axis=0).round(3) * 100
                            
                            # Visualize proportions
                            fig, ax = plt.subplots(figsize=(12, 8))
                            cohort_pct.plot(kind='bar', stacked=True, ax=ax)
                            ax.set_title(f'Monthly Cohort Composition by {field1_label} (%)')
                            ax.set_xlabel('Month')
                            ax.set_ylabel('Percentage')
                            plt.legend(title=field1_label)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Monthly Cohort Composition (%)',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Add tables with cohort data
                            stats = f"""
                            <div class="mb-4">
                                <h5>Cohort Size by Month</h5>
                                <div class="table-responsive">
                                    {cohort_pivot.to_html(classes='table table-striped table-hover table-bordered')}
                                </div>
                            </div>
                            <div class="mb-4">
                                <h5>Cohort Composition by Month (%)</h5>
                                <div class="table-responsive">
                                    {cohort_pct.to_html(classes='table table-striped table-hover table-bordered')}
                                </div>
                            </div>
                            """
                        
                        elif field_types[field1] == 'numeric':
                            # Convert to numeric
                            df[field1] = pd.to_numeric(df[field1], errors='coerce')
                            
                            # For numeric fields, create value range cohorts
                            if pd.notna(df[field1]).any():
                                # Create bins for the numeric field (5 equal-width bins)
                                min_val = df[field1].min()
                                max_val = df[field1].max()
                                
                                # Create 5 bins with nice round numbers
                                bins = 5
                                bin_width = (max_val - min_val) / bins
                                
                                # Create bin labels
                                bin_edges = [min_val + i * bin_width for i in range(bins + 1)]
                                bin_labels = [f'{bin_edges[i]:.1f} - {bin_edges[i+1]:.1f}' for i in range(bins)]
                                
                                # Create cohort groups
                                df['value_cohort'] = pd.cut(
                                    df[field1], 
                                    bins=bins, 
                                    labels=bin_labels
                                )
                                
                                # Extract month
                                df['cohort_month'] = pd.to_datetime(df['created_at']).dt.to_period('M')
                                
                                # Count by cohort and month
                                numeric_cohort = (
                                    df.groupby(['cohort_month', 'value_cohort'])
                                    .size()
                                    .reset_index(name='count')
                                )
                                
                                # Create pivot table
                                cohort_pivot = numeric_cohort.pivot_table(
                                    index='cohort_month', 
                                    columns='value_cohort', 
                                    values='count', 
                                    aggfunc='sum'
                                ).fillna(0)
                                
                                # Visualization
                                fig, ax = plt.subplots(figsize=(12, 8))
                                cohort_pivot.plot(kind='bar', stacked=True, ax=ax)
                                ax.set_title(f'Monthly Cohorts by {field1_label} Ranges')
                                ax.set_xlabel('Month')
                                ax.set_ylabel('Number of Submissions')
                                plt.legend(title=f'{field1_label} Range')
                                plt.xticks(rotation=45, ha='right')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Monthly Cohort Analysis by Value Range',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Add cohort data table
                                stats = f"""
                                <div class="mb-4">
                                    <h5>Cohort Size by Month and {field1_label} Range</h5>
                                    <div class="table-responsive">
                                        {cohort_pivot.to_html(classes='table table-striped table-hover table-bordered')}
                                    </div>
                                </div>
                                """
                            else:
                                stats = "<div class='alert alert-warning'>No valid numeric data available for cohort analysis.</div>"
                        else:
                            stats = f"<div class='alert alert-warning'>The field '{field1_label}' is not suitable for cohort analysis. Please select a categorical or numeric field.</div>"
    
    # Log the analytics view
    log_activity('view', 'analytics', None, {
        'project_id': project_id,
        'form_id': form_id,
        'analysis_type': analysis_type
    })
    
    return render_template(
        'analytics.html',
        projects=all_projects,
        forms=forms,
        all_fields=all_fields,
        field_types=field_types,
        stats=stats,
        plots=plots,
        title=title,
        selected_project=project_id,
        selected_form=form_id,
        selected_analysis=analysis_type,
        selected_field1=field1,
        selected_field2=field2,
        start_date=start_date,
        end_date=end_date,
        correlation_fields=correlation_fields
    )

@app.route('/export_analytics')
@login_required
def export_analytics():
    """Export analytics results as CSV, Excel or PNG"""
    if not current_user.is_admin:
        flash('You do not have permission to export analytics.', 'danger')
        return redirect(url_for('index'))
    
    # Get parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    analysis_type = request.args.get('analysis_type')
    field1 = request.args.get('field1')
    field2 = request.args.get('field2')
    export_format = request.args.get('format', 'excel')  # Default to excel
    
    # Get correlation fields (multiple selection)
    # For backward compatibility, handle both single and multiple field selections
    correlation_fields = request.args.getlist('correlation_fields[]')
    
    # Log export action
    log_details = f"Export Analytics - Project: {project_id or 'All'}, Form: {form_id or 'All'}, Analysis: {analysis_type}"
    log_activity('generate', 'analytics_export', None, log_details)
    
    # Prepare dataset
    df = prepare_dataset_for_analysis(project_id, form_id, start_date, end_date)
    
    # Generate filename
    filename = 'analytics'
    if project_id:
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            project_name = project_response.data[0]['name']
            filename = f"{project_name}_analytics"
    
    if form_id:
        form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
        if form_response.data:
            form_title = form_response.data[0]['title']
            filename = f"{filename}_{form_title}"
    
    if analysis_type:
        filename = f"{filename}_{analysis_type}"
    
    if field1:
        field1_name = field1.split(' - ')[-1] if ' - ' in field1 else field1
        filename = f"{filename}_{field1_name}"
    
    if field2 and analysis_type == 'crosstab':
        field2_name = field2.split(' - ')[-1] if ' - ' in field2 else field2
        filename = f"{filename}_{field2_name}"
    
    # Remove special characters from filename
    filename = re.sub(r'[^a-zA-Z0-9_]', '_', filename)
    
    # Export based on format
    if export_format == 'csv':
        output = StringIO()
        
        # Export different types of analysis
        if analysis_type == 'correlation':
            # If no correlation fields are selected, use all numeric fields
            if not correlation_fields:
                selected_numeric_fields = [field for field in df.columns if np.issubdtype(df[field].dtype, np.number)]
            else:
                selected_numeric_fields = correlation_fields
            
            if len(selected_numeric_fields) >= 2:
                # Convert fields to numeric before correlation
                numeric_df = df[selected_numeric_fields].apply(pd.to_numeric, errors='coerce')
                corr_matrix = numeric_df.corr().round(3)
                
                # Extract just the variable names (without project and form prefixes)
                clean_labels = []
                for field in selected_numeric_fields:
                    # Split by hyphen and get the last part which should be the variable name
                    if ' - ' in field:
                        parts = field.split(' - ')
                        clean_labels.append(parts[-1])  # Get only the last part (variable name)
                    else:
                        clean_labels.append(field)
                
                # Create a clean correlation matrix with variable names only for display
                clean_corr_matrix = corr_matrix.copy()
                clean_corr_matrix.index = clean_labels
                clean_corr_matrix.columns = clean_labels
                
                clean_corr_matrix.to_csv(output)
        elif analysis_type == 'crosstab' and field1 and field2:
            # Export crosstab
            if field1 in df.columns and field2 in df.columns:
                ct = pd.crosstab(df[field1], df[field2])
                ct.to_csv(output)
        elif analysis_type == 'timeseries' and field1:
            # Export time series data
            if 'created_at' in df.columns and field1 in df.columns:
                df['date'] = pd.to_datetime(df['created_at']).dt.date
                time_data = df.groupby('date')[field1].agg(['mean', 'count', 'std', 'min', 'max']).reset_index()
                time_data.to_csv(output, index=False)
        else:
            # Default: export the filtered dataset
            df.to_csv(output, index=False)
        
        output.seek(0)
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"{filename}.csv"
        )
        
    elif export_format == 'excel':
        output = BytesIO()
        
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Write the main dataset
            df.to_excel(writer, sheet_name='Data', index=False)
            
            # Get workbook and create a left-aligned format for headers
            workbook = writer.book
            header_format = workbook.add_format({
                'bold': True,
                'align': 'left',
                'valign': 'vcenter',
                'fg_color': '#D7E4BC',
                'border': 1
            })
            
            # Add analysis-specific sheets
            if analysis_type == 'correlation':
                # If no correlation fields are selected, use all numeric fields
                if not correlation_fields:
                    selected_numeric_fields = [field for field in df.columns if np.issubdtype(df[field].dtype, np.number)]
                else:
                    selected_numeric_fields = correlation_fields
                
                if len(selected_numeric_fields) >= 2:
                    # Convert fields to numeric before correlation
                    numeric_df = df[selected_numeric_fields].apply(pd.to_numeric, errors='coerce')
                    corr_matrix = numeric_df.corr().round(3)
                    
                    # Extract just the variable names (without project and form prefixes)
                    clean_labels = []
                    for field in selected_numeric_fields:
                        # Split by hyphen and get the last part which should be the variable name
                        if ' - ' in field:
                            parts = field.split(' - ')
                            clean_labels.append(parts[-1])  # Get only the last part (variable name)
                        else:
                            clean_labels.append(field)
                    
                    # Create a clean correlation matrix with variable names only for display
                    clean_corr_matrix = corr_matrix.copy()
                    clean_corr_matrix.index = clean_labels
                    clean_corr_matrix.columns = clean_labels
                    
                    clean_corr_matrix.to_excel(writer, sheet_name='Correlation Matrix')
                    
                    # Apply header formatting
                    worksheet = writer.sheets['Correlation Matrix']
                    for col_num, value in enumerate([''] + clean_labels):
                        worksheet.write(0, col_num, value, header_format)
                    
            elif analysis_type == 'crosstab' and field1 and field2:
                if field1 in df.columns and field2 in df.columns:
                    ct = pd.crosstab(df[field1], df[field2])
                    ct.to_excel(writer, sheet_name='Cross Tabulation')
                    
                    # Apply header formatting
                    worksheet = writer.sheets['Cross Tabulation']
                    for col_num, value in enumerate([''] + list(ct.columns)):
                        worksheet.write(0, col_num, value, header_format)
                    
            elif analysis_type == 'summary_statistics' and field1:
                if field1 in df.columns:
                    # Create a summary sheet
                    numeric_data = pd.to_numeric(df[field1], errors='coerce').dropna()
                    if len(numeric_data) > 0:
                        stats = {
                            'Statistic': ['Count', 'Missing', 'Mean', 'Median', 'Std Dev', 'Min', 'Max', 
                                        '25th Percentile', '75th Percentile'],
                            'Value': [
                                len(numeric_data),
                                len(df) - len(numeric_data),
                                numeric_data.mean(),
                                numeric_data.median(),
                                numeric_data.std(),
                                numeric_data.min(),
                                numeric_data.max(),
                                numeric_data.quantile(0.25),
                                numeric_data.quantile(0.75)
                            ]
                        }
                        pd.DataFrame(stats).to_excel(writer, sheet_name='Summary Stats', index=False)
                        
                        # Apply header formatting
                        worksheet = writer.sheets['Summary Stats']
                        for col_num, value in enumerate(stats.keys()):
                            worksheet.write(0, col_num, value, header_format)
                        
            elif analysis_type == 'timeseries' and field1:
                if 'created_at' in df.columns and field1 in df.columns:
                    df['date'] = pd.to_datetime(df['created_at']).dt.date
                    time_data = df.groupby('date')[field1].agg(['mean', 'count', 'std', 'min', 'max']).reset_index()
                    time_data.to_excel(writer, sheet_name='Time Series', index=False)
                    
                    # Apply header formatting
                    worksheet = writer.sheets['Time Series']
                    for col_num, value in enumerate(time_data.columns):
                        worksheet.write(0, col_num, value, header_format)
            
            # Apply header formatting to main data sheet
            worksheet = writer.sheets['Data']
            for col_num, value in enumerate(df.columns):
                worksheet.write(0, col_num, value, header_format)
                
                # Auto-adjust column width based on content
                col_width = max(
                    len(str(value)),
                    df[value].astype(str).str.len().max() if not df.empty else 0
                ) + 2
                worksheet.set_column(col_num, col_num, min(col_width, 30))  # Cap width at 30
        
        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f"{filename}.xlsx"
        )
    
    # Unsupported format
    flash('Unsupported export format', 'danger')
    return redirect(url_for('analytics', 
                           project_id=project_id, 
                           form_id=form_id,
                           start_date=start_date,
                           end_date=end_date,
                           analysis_type=analysis_type,
                           field1=field1,
                           field2=field2))

@app.route('/admin/clear-activity-logs', methods=['POST'])
@login_required
def clear_activity_logs():
    """Clear all activity logs except the admin's current session logs"""
    if not current_user.is_admin:
        flash('You do not have permission to clear activity logs.', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Get all existing log IDs so we can delete them one by one
        logs_response = supabase.table('log_activities').select('id').execute()
        if logs_response.data:
            log_ids = [log['id'] for log in logs_response.data]
            
            # Delete logs in batches to avoid potential issues with large deletes
            batch_size = 50
            for i in range(0, len(log_ids), batch_size):
                batch = log_ids[i:i + batch_size]
                for log_id in batch:
                    supabase.table('log_activities').delete().eq('id', log_id).execute()
        
        # Create an entry to record that logs were cleared
        clear_log_entry = {
            'id': str(uuid.uuid4()),
            'user_id': current_user.id,
            'username': current_user.username,
            'action': 'clear',
            'entity_type': 'activity_logs',
            'details': f"All previous activity logs cleared by {current_user.username}",
            'ip_address': request.remote_addr
        }
        
        # Insert the clearing activity log
        supabase.table('log_activities').insert(clear_log_entry).execute()
        
        flash('Activity logs have been cleared successfully.', 'success')
    except Exception as e:
        flash(f'Error clearing activity logs: {str(e)}', 'danger')
    
    return redirect(url_for('activity_logs'))

@app.route('/api/form/<form_id>/details')
@login_required
def get_form_details(form_id):
    """API endpoint to fetch form details (title and fields) for editing."""
    try:
        print(f"API: Fetching details for form {form_id}")
        # Correctly indent the chained call
        form_response = (
            supabase.table('forms')
            .select('title, fields')
            .eq('id', form_id)
            .single()  # Use single() to get one record or raise error
            .execute()
        )

        # single() will raise an error if not found or multiple found
        form_data = form_response.data
        print(f"API: Found form data: {form_data}")

        # Parse the fields JSON string
        if isinstance(form_data.get('fields'), str):
            try:
                form_data['fields'] = json.loads(form_data['fields'])
            except json.JSONDecodeError as e:
                print(f"API: Error parsing fields JSON for form {form_id}: {str(e)}")
                # Return fields as an empty list if parsing fails
                form_data['fields'] = [] 
        elif not isinstance(form_data.get('fields'), list):
             # If it's not a string and not a list, default to empty list
             print(f"API: Fields data for form {form_id} is not a string or list, defaulting to empty.")
             form_data['fields'] = []

        return jsonify({
            'title': form_data.get('title', ''),
            'fields': form_data.get('fields', [])
        })

    except Exception as e:
        # Check if the error indicates 'PGRST116' (JSON object requested, multiple (or no) rows returned)
        # This handles the case where single() fails because the form_id doesn't exist
        error_message = str(e)
        print(f"API: Error fetching form details for {form_id}: {error_message}")
        if 'PGRST116' in error_message or 'NotFound' in error_message: # Adapt based on actual Supabase client errors
            return jsonify({'error': 'Form not found'}), 404
        else:
            return jsonify({'error': 'An internal error occurred'}), 500

@app.route('/form/<form_id>/edit', methods=['POST'])
@login_required
def edit_form(form_id):
    """Handles the submission of the edited form details."""
    if not current_user.is_admin:
        flash('Admin access required to edit forms.', 'danger')
        return redirect(url_for('index'))

    # Fetch the project_id associated with this form for redirection
    project_id = None
    try:
        form_response = supabase.table('forms').select('project_id').eq('id', form_id).single().execute()
        project_id = form_response.data['project_id']
    except Exception as e:
        print(f"Error fetching project_id for form {form_id}: {str(e)}")
        flash('Error finding the associated project. Cannot edit form.', 'danger')
        # Redirect to admin dashboard if project_id is unknown
        return redirect(url_for('admin_dashboard')) 

    try:
        title = request.form.get('title')
        labels = request.form.getlist('field_labels[]')
        types = request.form.getlist('field_types[]')
        options_list = request.form.getlist('field_options[]')
        location_identifiers = request.form.getlist('location_field_identifier[]') # Read the identifiers
        
        # Basic validation
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        if not labels:
            flash('At least one field is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        
        # Process fields into JSON (same logic as create_form)
        fields = []
        location_idx = 0 
        for i in range(len(labels)):
            field = {
                'label': labels[i].strip(),
                'type': types[i],
                'options': [opt.strip() for opt in options_list[i].split(',') if opt.strip()] if types[i] in ['dropdown', 'radio', 'checkbox'] else []
            }
            if labels[i] in ['Region', 'District', 'Ward'] and location_idx < len(location_identifiers):
                 field['location_field_identifier'] = location_identifiers[location_idx]
                 field['type'] = 'dropdown' 
                 field['options'] = []
                 location_idx += 1
            else:
                 field['location_field_identifier'] = None
            fields.append(field)
            
        serialized_fields = json.dumps(fields)
        print(f"Updating form {form_id} with fields: {serialized_fields}")
        
        # Update form record in database
        update_data = {
            'title': title,
            'fields': serialized_fields
            # Optionally update a modified_at timestamp here if you add one
        }
        
        response = supabase.table('forms').update(update_data).eq('id', form_id).execute()
        
        # Check if update was successful (response structure might vary, adjust if needed)
        if response.data: # Check if data is returned on successful update
            log_activity('update', 'form', form_id, f"Updated form title: {title}")
            flash('Form updated successfully.', 'success')
        else:
            # Supabase update might return empty data on success, 
            # or have specific error info. Check client documentation.
            # Assuming empty data on success for now, but log potential issues.
            print(f"Form update response for {form_id}: {response}") # Log response for debugging
            # Check for specific error conditions if the Supabase client provides them
            if hasattr(response, 'error') and response.error:
                 flash(f'Failed to update form: {response.error.message}', 'danger')
            else:
                # Assume success if no explicit error, log activity
                log_activity('update', 'form', form_id, f"Updated form title: {title}")
                flash('Form updated successfully (no data returned). ', 'success')
                
    except Exception as e:
        print(f"Error updating form {form_id}: {str(e)}")
        flash(f'An error occurred while updating the form: {str(e)}', 'danger')
    
    # Redirect back to the project detail page
    return redirect(url_for('project_detail', project_id=project_id))

# Correctly indented start of the main execution block
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Set debug=False for production