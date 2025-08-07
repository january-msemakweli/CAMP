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
# Set matplotlib parameters for better rendering
plt.rcParams['figure.dpi'] = 100
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['figure.autolayout'] = True
import matplotlib.ticker as ticker
import seaborn as sns
# Configure seaborn
sns.set_style('whitegrid')
sns.set_context('notebook', font_scale=1.2)
import base64
from io import BytesIO, StringIO
import time
import re
from collections import Counter
import traceback
import urllib.parse

# Set default timezone to GMT+3 (East African Time)
EAT = timezone(timedelta(hours=3))

# Load environment variables
load_dotenv()

def fetch_all_pages(query, page_size=1000, debug_name="query", max_retries=3, timeout_seconds=300):
    """
    FIXED: Fetch all pages using the exact same logic as dataset view manual pagination.
    
    Args:
        query: Supabase query object (before .execute())
        page_size: Number of records per page (default 1000)
        debug_name: Name for debug logging
        max_retries: Maximum retry attempts for failed pages
        timeout_seconds: Timeout for individual page requests
        
    Returns:
        List of all records across all pages
    """
    all_data = []
    start = 0
    
    print(f"{debug_name}: Starting pagination with page_size={page_size}")
    
    while True:
        try:
            print(f"{debug_name}: Fetching page starting at {start}")
            page_response = query.range(start, start + page_size - 1).execute()
            page_data = page_response.data
            
            if not page_data:
                print(f"{debug_name}: No more data at start={start}, pagination complete")
                break
                
            all_data.extend(page_data)
            print(f"{debug_name}: Successfully fetched page starting at {start}: {len(page_data)} records (Total so far: {len(all_data)})")
            
            # CRITICAL DEBUG: For report submissions, print sample patient IDs
            if debug_name == "report_submissions" and len(page_data) > 0:
                sample_patient_ids = [item.get('patient_id') for item in page_data[:5] if item.get('patient_id')]
                print(f"REPORT DEBUG: Sample patient IDs from this page: {sample_patient_ids}")
            
            # Continue fetching if we got a full page OR if we got exactly 999 (possible Supabase limit)
            if len(page_data) < page_size and len(page_data) != 999:
                print(f"{debug_name}: Got {len(page_data)} records (less than {page_size}), pagination complete")
                break
                
            start += page_size
            
            # Safety limit to prevent infinite loops
            if start > 500000:  # 500K record safety limit
                print(f"{debug_name}: CRITICAL WARNING - Reached 500,000 records, investigating...")
                if len(page_data) == page_size:
                    print(f"{debug_name}: Still getting full pages, continuing with caution...")
                    continue
                else:
                    print(f"{debug_name}: Page size reduced, safe to break")
                break
                
        except Exception as e:
            print(f"{debug_name}: Error fetching page starting at {start}: {str(e)}")
            break
    
    print(f"{debug_name}: Total records fetched: {len(all_data)}")
    return all_data

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# PERFORMANCE FIX: Initialize Supabase client with enhanced timeout configuration
try:
    # Try with advanced options first
    from supabase._sync.client import ClientOptions
    from httpx import Timeout
    
    client_options = ClientOptions(
        postgrest_client_timeout=300,  # 5 minutes for large datasets
        storage_client_timeout=300,
    )
    
    supabase: Client = create_client(
        os.getenv('SUPABASE_URL'),
        os.getenv('SUPABASE_KEY'),
        options=client_options
    )
    print("Supabase client initialized with enhanced timeout settings")
    
except (ImportError, AttributeError, TypeError) as e:
    # Fallback to basic client initialization if advanced options not supported
    print(f"Advanced Supabase options not supported, using basic client: {str(e)}")
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
    """
    This function is disabled to prevent automatic table creation attempts.
    Use the SQL scripts (fix_project_access.sql, fix.sql, fix_simple.sql) to create tables manually.
    """
    print("Automatic table creation is disabled. Use SQL scripts to create tables manually.")
    pass

def ensure_admin_user():
    """Create admin user if it doesn't exist"""
    try:
        print("Checking for admin user...")
        
        # Check if admin user exists
        response = supabase.table('users').select('*').eq('username', 'admin').execute()
        if not response.data:
            print("Admin user not found. Creating admin user...")
            
            # Create admin user with default password 'admin'
            admin_id = str(uuid.uuid4())
            admin_user = {
                'id': admin_id,
                'username': 'admin',
                'password': generate_password_hash('moafya123'),
                'is_admin': True,
                'is_approved': True
            }
            
            # Insert admin user
            supabase.table('users').insert(admin_user).execute()
            print("Admin user created successfully with default password 'moafya123'")
            print("IMPORTANT: Please change the admin password after first login")
        else:
            print("Admin user exists")
    except Exception as e:
        print(f"Error checking/creating admin user: {str(e)}")
        print("Using fallback authentication system instead.")

def check_database_structure():
    """Check if required tables exist but don't attempt to create them"""
    print("Checking database structure (read-only)...")
    
    try:
        # Only check if tables exist but don't create them
        tables_to_check = ['users', 'projects', 'forms', 'form_submissions', 
                          'form_permissions', 'registration_permissions', 'log_activities', 'patients']
        
        for table in tables_to_check:
            try:
                # Just check if we can access the table
                # Special case for patients table which has patient_id as primary key, not id
                if table == 'patients':
                    response = supabase.table(table).select('patient_id').limit(1).execute()
                else:
                    response = supabase.table(table).select('id').limit(1).execute()
                print(f"Table {table} exists.")
            except Exception as e:
                print(f"Table {table} error: {str(e)}")
        
        print("Database check completed.")
    except Exception as e:
        print(f"Error checking database structure: {str(e)}")

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

def get_form_is_first(form_id):
    """Check if a form is the first (registration) form in its project"""
    # Use function attribute as cache
    if not hasattr(get_form_is_first, 'cache'):
        get_form_is_first.cache = {}
    
    if not form_id:
        return False
    
    # Return from cache if available
    if form_id in get_form_is_first.cache:
        return get_form_is_first.cache[form_id]
    
    try:
        # Get the form's details including title
        form_response = supabase.table('forms').select('project_id, title').eq('id', form_id).execute()
        if not form_response.data:
            print(f"Form {form_id} not found when checking if it's a first form")
            get_form_is_first.cache[form_id] = False
            return False
        
        form_data = form_response.data[0]
        project_id = form_data['project_id']
        form_title = form_data.get('title', '').lower()
        
        # Check if the form title contains keywords suggesting it's a registration form
        registration_keywords = ['registration', 'register', 'first', 'initial', 'intake', 'create']
        title_suggests_registration = any(keyword in form_title for keyword in registration_keywords)
        
        # Get all forms for this project ordered by creation date
        forms_query = supabase.table('forms').select('id, title').eq('project_id', project_id).order('created_at')
        all_forms_data = fetch_all_pages(forms_query, debug_name=f"form_is_first_project_{project_id}")
        if not all_forms_data or len(all_forms_data) == 0:
            print(f"No forms found for project {project_id} when checking if form {form_id} is first")
            get_form_is_first.cache[form_id] = False
            return False
        
        # Check if form is the first created in its project
        is_first_by_order = all_forms_data[0]['id'] == form_id
        
        # Log the decision process
        if is_first_by_order:
            print(f"Form {form_id} '{form_title}' is first form by creation order in project {project_id}")
        elif title_suggests_registration:
            print(f"Form {form_id} '{form_title}' is identified as registration form by title keywords")
            
        # Consider a form "first" if either it's the first created or its title suggests it's for registration
        result = is_first_by_order or title_suggests_registration
        get_form_is_first.cache[form_id] = result
        return result
    except Exception as e:
        print(f"Error checking if form is first: {str(e)}")
        get_form_is_first.cache[form_id] = False
        return False

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

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

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

@app.route('/register_patient')
@login_required
def register_patient_form():
    """Display the centralized patient registration form"""
    # Check if user has registration access (admins always have access)
    if not current_user.is_admin:
        access_response = supabase.table('registration_permissions').select('*').eq('user_id', current_user.id).execute()
        if not access_response.data:
            flash('You do not have access to patient registration', 'danger')
            return redirect(url_for('user_dashboard'))
    
    return render_template('register_patient.html')

@app.route('/register_patient', methods=['POST'])
@login_required 
def submit_patient_registration():
    """Handle centralized patient registration submission"""
    # Check if user has registration access (admins always have access)
    if not current_user.is_admin:
        access_response = supabase.table('registration_permissions').select('*').eq('user_id', current_user.id).execute()
        if not access_response.data:
            flash('You do not have permission to register patients', 'danger')
            return redirect(url_for('user_dashboard'))
    
    try:
        # Get patient ID from form
        patient_id = request.form.get('patient_id')
        if not patient_id:
            flash('Patient ID is required', 'danger')
            return redirect(url_for('register_patient_form'))

        # Define exact registration fields as specified
        registration_fields = [
            {'label': 'Name', 'type': 'text', 'required': False},
            {'label': 'Age (Years)', 'type': 'number', 'required': True},
            {'label': 'Gender', 'type': 'radio', 'required': True},
            {'label': 'Region', 'type': 'dropdown', 'required': True},
            {'label': 'District', 'type': 'dropdown', 'required': True},
            {'label': 'Ward', 'type': 'dropdown', 'required': True},
            {'label': 'Phone Number', 'type': 'text', 'required': False}
        ]
        
        # Collect registration data
        registration_data = {}
        validation_errors = []
        
        for field in registration_fields:
            field_label = field['label']
            field_value = request.form.get(field_label, '').strip()
            
            # Validate required fields
            if field['required'] and not field_value:
                validation_errors.append(f"{field_label} is required")
            
            # Store the value (empty string converted to None for consistency)
            registration_data[field_label] = field_value if field_value else None
        
        if validation_errors:
            for error in validation_errors:
                flash(error, 'danger')
            return redirect(url_for('register_patient_form'))

        # Check if patient already exists
        patient_response = supabase.table('patients').select('*').eq('patient_id', patient_id).execute()
        
        if patient_response.data:
            # Patient exists, update registration data
            patient_record = patient_response.data[0]
            patient_data = patient_record.get('data', {})
            patient_data['registration'] = registration_data
            
            supabase.table('patients').update({'data': patient_data}).eq('patient_id', patient_id).execute()
            flash(f'Registration updated for patient {patient_id}', 'success')
        else:
            # Create new patient record with registration data
            new_patient = {
                'patient_id': patient_id,
                'data': {'registration': registration_data}
            }
            supabase.table('patients').insert(new_patient).execute()
            flash(f'Patient {patient_id} registered successfully', 'success')
        
        # Log the registration
        log_activity('register', 'patient', patient_id, f"Patient registration: {registration_data.get('Name', 'Unknown')}")
        
        return redirect(url_for('register_patient_form'))
        
    except Exception as e:
        print(f"Error in patient registration: {str(e)}")
        flash(f'Error registering patient: {str(e)}', 'danger')
        return redirect(url_for('register_patient_form'))

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
    
    # Get all users using pagination
    all_users = fetch_all_pages(supabase.table('users').select('*'), debug_name="admin_dashboard_users")
    
    # Get all projects using pagination
    projects = fetch_all_pages(supabase.table('projects').select('*'), debug_name="admin_dashboard_projects")
    
    # Get recent camps for the camps management section
    recent_camps = fetch_all_pages(
        supabase.table('camps').select('*').order('created_at', desc=True).limit(5),
        debug_name="admin_dashboard_recent_camps"
    )
    
    return render_template('admin_dashboard.html', 
                         pending_users=pending_users,
                         all_users=all_users,
                         projects=projects,
                         recent_camps=recent_camps)

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
        return redirect(url_for('projects'))
    
    project = project_response.data[0]
    # Remove camp_date if it exists in the fetched data
    project.pop('camp_date', None)
    
    # Get forms for this project, excluding archived forms
    forms_query = supabase.table('forms').select('*').eq('project_id', project_id).eq('is_archived', False).order('created_at')
    forms = fetch_all_pages(forms_query, debug_name=f"project_detail_{project_id}_forms")
    
    # Parse the fields for each form
    for form in forms:
        if isinstance(form['fields'], str):
            try:
                form['fields'] = json.loads(form['fields'])
            except Exception as e:
                print(f"Error parsing form fields: {str(e)}")
                form['fields'] = []
    
    # For admins, get users who have access to this project
    project_access = []
    users = []
    if current_user.is_admin:
        # Get users with access to this project
        access_response = supabase.table('user_project_access').select('*').eq('project_id', project_id).execute()
        
        for access in access_response.data:
            # Get user details
            user_response = supabase.table('users').select('username').eq('id', access['user_id']).execute()
            if user_response.data:
                access['users'] = user_response.data[0]
                project_access.append(access)
        
        # Get all approved users for the dropdown using pagination
        users = fetch_all_pages(supabase.table('users').select('*').eq('is_approved', True), debug_name="project_detail_users")
    
    log_activity('view', 'project', project_id, f"Project: {project['name']}")
    
    return render_template('project_detail.html', 
                           project=project, 
                           forms=forms,
                           project_access=project_access,
                           users=users)

@app.route('/project/<project_id>/grant_access', methods=['POST'])
@login_required
def grant_project_access(project_id):
    """Grant access to a project for a specific user"""
    # Ensure user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to manage project access.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))
    
    try:
        user_id = request.form.get('user_id')
        if not user_id:
            flash('No user selected.', 'warning')
            return redirect(url_for('project_detail', project_id=project_id))
        
        # Check if project exists
        project_response = supabase.table('projects').select('*').eq('id', project_id).execute()
        if not project_response.data:
            flash('Project not found.', 'danger')
            return redirect(url_for('projects'))
        
        # Check if access already exists
        existing_access = supabase.table('user_project_access').select('*').eq('project_id', project_id).eq('user_id', user_id).execute()
        
        if existing_access.data:
            flash('User already has access to this project.', 'warning')
            return redirect(url_for('project_detail', project_id=project_id))
        
        # Generate unique ID for the access record
        access_id = str(uuid.uuid4())
        
        # Create access record
        access_data = {
            'id': access_id,
            'project_id': project_id,
            'user_id': user_id
        }
        
        # Insert into database
        supabase.table('user_project_access').insert(access_data).execute()
        
        # Log the activity
        user_response = supabase.table('users').select('username').eq('id', user_id).execute()
        username = user_response.data[0]['username'] if user_response.data else 'Unknown User'
        
        log_activity('grant_access', 'project', project_id, f"Granted access to user: {username}")
        
        flash(f'Access granted to {username}.', 'success')
        
    except Exception as e:
        print(f"Error granting project access: {str(e)}")
        flash(f'An error occurred while granting access: {str(e)}', 'danger')
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<project_id>/revoke_access/<access_id>', methods=['POST'])
@login_required
def revoke_project_access(project_id, access_id):
    """Revoke access to a project for a specific user"""
    # Ensure user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to manage project access.', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))
    
    try:
        # Get the access record to identify the user whose access is being revoked
        access_response = supabase.table('user_project_access').select('*, users(username)').eq('id', access_id).execute()
        
        if not access_response.data:
            flash('Access record not found.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        
        access = access_response.data[0]
        username = access.get('users', {}).get('username', 'Unknown User')
        
        # Delete the access record
        supabase.table('user_project_access').delete().eq('id', access_id).execute()
        
        # Log the activity
        log_activity('revoke_access', 'project', project_id, f"Revoked access for user: {username}")
        
        flash(f'Access revoked for {username}.', 'success')
        
    except Exception as e:
        print(f"Error revoking project access: {str(e)}")
        flash(f'An error occurred while revoking access: {str(e)}', 'danger')
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/project/<project_id>/create_form', methods=['POST'])
@login_required
def create_form(project_id):
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    try:
        title = request.form.get('title')
        
        # Check if we have the new structured fields_data
        fields_data_json = request.form.get('fields_data')
        if fields_data_json:
            print(f"🆕 CREATE: Using NEW field-centric approach")
            try:
                fields = json.loads(fields_data_json)
                print(f"✅ CREATE: Received {len(fields)} structured fields:")
                for i, field in enumerate(fields):
                    print(f"  Field {i}: {field['label']} - Condition: {field.get('condition', 'None')}")
                    
            except json.JSONDecodeError as e:
                print(f"❌ CREATE: JSON decode error: {e}")
                flash('Invalid fields data format.', 'danger')
                return redirect(url_for('project_detail', project_id=project_id))
        else:
            print(f"🔄 CREATE: Using OLD array approach (fallback)")
            # Fall back to old approach for compatibility
        labels = request.form.getlist('field_labels[]')
        types = request.form.getlist('field_types[]')
        options_list = request.form.getlist('field_options[]')
        location_identifiers = request.form.getlist('location_field_identifier[]')
        required_fields = request.form.getlist('field_required[]')
        allow_other_fields = request.form.getlist('allow_other[]')
        
        # Conditional field data
        is_conditional_fields = request.form.getlist('is_conditional[]')
        condition_fields = request.form.getlist('condition_field[]')
        condition_operators = request.form.getlist('condition_operator[]')
        condition_values = request.form.getlist('condition_value[]')
        condition_logic = request.form.getlist('condition_logic[]')
        
        # Debug conditional fields data (OLD APPROACH)
        print(f"🔍 FORM SUBMISSION DEBUG:")
        print(f"DEBUG - Total fields: {len(labels)}")
        print(f"DEBUG - Labels: {labels}")
        print(f"DEBUG - is_conditional_fields: {is_conditional_fields}")
        print(f"DEBUG - condition_fields: {condition_fields}")
        print(f"DEBUG - condition_operators: {condition_operators}")
        print(f"DEBUG - condition_values: {condition_values}")
        print(f"DEBUG - condition_logic: {condition_logic}")
        print(f"DEBUG - required_fields: {required_fields}")
        print(f"DEBUG - allow_other_fields: {allow_other_fields}")
        
        # Debug: show exactly which fields should have conditions
        for i, conditional_field_idx in enumerate(is_conditional_fields):
                if conditional_field_idx and int(conditional_field_idx) < len(labels):
                    field_name = labels[int(conditional_field_idx)]
                    print(f"🎯 Conditional field #{conditional_field_idx}: '{field_name}'")
                    if i < len(condition_fields):
                        print(f"   ➜ Should depend on: '{condition_fields[i]}'")
                    if i < len(condition_operators):
                        print(f"   ➜ Operator: '{condition_operators[i]}'")
                    if i < len(condition_values):
                        print(f"   ➜ Value: '{condition_values[i]}'")
                    if i < len(condition_logic):
                        print(f"   ➜ Logic: '{condition_logic[i]}'")
                    print()
                    
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
            
        # Validation for new approach
        if fields_data_json:
            if not fields:
                flash('At least one field is required.', 'danger')
                return redirect(url_for('project_detail', project_id=project_id))
        # Validation for old approach  
        else:
            if not labels:
                flash('At least one field is required.', 'danger')
                return redirect(url_for('project_detail', project_id=project_id))
            
        # Process fields based on approach
        if fields_data_json:
            # NEW APPROACH: fields are already structured and ready
            print(f"✅ CREATE: Using structured fields directly")
        else:
            # OLD APPROACH: build fields from arrays
            fields = []
            location_idx = 0
            for i in range(len(labels)):
                field = {
                    'label': labels[i].strip(),
                    'type': types[i],
                    'options': [opt.strip() for opt in options_list[i].split(',') if opt.strip()] if types[i] in ['dropdown', 'radio', 'checkbox'] else [],
                    'required': str(i) in required_fields
                }
                if types[i] in ['radio', 'checkbox']:
                    field['allow_other'] = str(i) in allow_other_fields
                if labels[i] in ['Region', 'District', 'Ward'] and location_idx < len(location_identifiers):
                    field['location_field_identifier'] = location_identifiers[location_idx]
                    field['type'] = 'dropdown'
                    field['options'] = []
                    location_idx += 1
                else:
                    field['location_field_identifier'] = None
                
                # Add conditional logic if this field is conditional
                is_in_conditional = str(i) in is_conditional_fields
                
                print(f"DEBUG - Field {i} ({labels[i]}):")
                print(f"  - str(i) = '{str(i)}'")
                print(f"  - is_conditional_fields = {is_conditional_fields}")
                print(f"  - is '{str(i)}' in conditional list? {is_in_conditional}")
                
                if is_in_conditional:
                        # Collect ALL conditions for this field (multiple conditions support)
                        field_conditions = []
                        field_logic = 'OR'  # Default logic
                        
                        print(f"  - Collecting all conditions for field {i}")
                        
                        # Strategy: collect conditions starting from conditional field position
                        
                        # Find the position of this field in the conditional fields list
                        try:
                            current_field_position = is_conditional_fields.index(str(i))
                            print(f"  - Field {i} is at conditional position {current_field_position}")
                            
                            # Find where the next conditional field's conditions start
                            next_condition_start = len(condition_fields)  # Default to end of array
                            if current_field_position + 1 < len(is_conditional_fields):
                                next_field_idx = int(is_conditional_fields[current_field_position + 1])
                                next_field_position = is_conditional_fields.index(str(next_field_idx))
                                next_condition_start = next_field_position
                                print(f"  - Next conditional field {next_field_idx} starts at condition position {next_condition_start}")
                            
                            # Collect ALL conditions for this field starting from its position
                            condition_start_idx = current_field_position
                            condition_end_idx = next_condition_start
                            
                            print(f"  - Collecting conditions from index {condition_start_idx} to {condition_end_idx-1}")
                            
                            for condition_idx in range(condition_start_idx, min(condition_end_idx, len(condition_fields))):
                                if (condition_idx < len(condition_fields) and 
                                    condition_idx < len(condition_operators) and 
                                    condition_idx < len(condition_values)):
                                    
                                    dependent_field = condition_fields[condition_idx].strip()
                                    operator = condition_operators[condition_idx] if condition_idx < len(condition_operators) else 'equals'
                                    value = condition_values[condition_idx] if condition_idx < len(condition_values) else ''
                                    
                                    # Only add condition if dependent field is not empty
                                    if dependent_field:
                                        condition_rule = {
                                            'dependent_field': dependent_field,
                                            'operator': operator,
                                            'value': value
                                        }
                                        field_conditions.append(condition_rule)
                                        print(f"  - Added condition {len(field_conditions)}: {condition_rule}")
                                        
                                        # Get logic for this field (use the first logic we encounter)
                                        if len(field_conditions) == 1 and condition_idx < len(condition_logic):
                                            field_logic = condition_logic[condition_idx]
                                            print(f"  - Using logic: {field_logic}")
                                    else:
                                        print(f"  - Skipping empty condition at index {condition_idx}")
                            
                            # Create the final condition structure
                            if field_conditions:
                                if len(field_conditions) == 1:
                                    # Single condition - use backward compatible format
                                    field['condition'] = field_conditions[0]
                                    print(f"  - RESULT: Field {i} has single condition: {field['condition']}")
                                else:
                                    # Multiple conditions - use new format with logic
                                    field['condition'] = {
                                        'logic': field_logic,
                                        'rules': field_conditions
                                    }
                                    print(f"  - RESULT: Field {i} has {len(field_conditions)} conditions with {field_logic} logic: {field['condition']}")
                            else:
                                field['condition'] = None
                                print(f"  - RESULT: Field {i} marked conditional but no valid conditions found")
                                
                        except ValueError:
                            field['condition'] = None
                            print(f"  - ERROR: Field {i} not found in conditional fields list!")
                else:
                    field['condition'] = None
                    print(f"  - RESULT: Field {i} is NOT conditional (condition set to null)")
                    
                fields.append(field)
                
        # Serialize fields (works for both new and old approaches)
        serialized_fields = json.dumps(fields)
        form_id = str(uuid.uuid4())
        form_data = {
            'id': form_id,
            'project_id': project_id,
            'title': title,
            'fields': serialized_fields
        }
        response = supabase.table('forms').insert(form_data).execute()
        if response.data:
            log_activity('create', 'form', form_id, f"Form title: {title}")
            flash('Form created successfully.', 'success')
        else:
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
        return redirect(url_for('user_dashboard'))
    
    form = form_response.data[0]
    
    # Parse the fields JSON string into Python objects
    if isinstance(form['fields'], str):
        try:
            form['fields'] = json.loads(form['fields'])
        except Exception as e:
            print(f"Error parsing form fields in view_form: {str(e)}")
            form['fields'] = []
    
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
    
    # Check if this is the first form in the project (for Patient ID workflow)
    # Get all forms for this project ordered by creation date
    forms_query = supabase.table('forms').select('id').eq('project_id', form['project_id']).order('created_at')
    all_project_forms = fetch_all_pages(forms_query, debug_name=f"view_form_project_{form['project_id']}_forms")
    is_first_form = False
    
    # Calculate form_index for the waitlist feature
    form_indices = {}
    if all_project_forms and len(all_project_forms) > 0:
        # Check if current form is the first one created
        is_first_form = all_project_forms[0]['id'] == form_id
        # Map form IDs to their positions in the sequence
        form_indices = {f['id']: idx for idx, f in enumerate(all_project_forms)}
        # Add form_index to form object
        form['form_index'] = form_indices.get(form_id, 0)
    
    # Get form submissions (limited to 5 most recent)
    submissions_response = supabase.table('form_submissions').select('*').eq('form_id', form_id).order('created_at', desc=True).limit(5).execute()
    submissions = submissions_response.data
    
    # If admin, get users for assignment - but only those with project access
    users = []
    user_permissions = []
    project_users = []
    
    if current_user.is_admin:
        # Get users with project access
        project_access_response = supabase.table('user_project_access').select('user_id').eq('project_id', form['project_id']).execute()
        
        if project_access_response.data:
            project_user_ids = [access['user_id'] for access in project_access_response.data]
            
            # Get details of users with project access
            if project_user_ids:
                # Convert list to comma-separated string for SQL in query
                user_ids_str = ','.join([f"'{uid}'" for uid in project_user_ids])
                users_response = supabase.table('users').select('*').eq('is_approved', True).in_('id', project_user_ids).execute()
                project_users = users_response.data
        
        # Get users with form permissions
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
    
    # Get waitlist visibility setting (default to False if not set)
    show_waitlist = form.get('show_waitlist', False)
    
    return render_template('view_form.html', 
                          form=form, 
                          project=project, 
                          submissions=submissions, 
                          users=project_users,  # Now only showing users with project access
                          user_permissions=user_permissions,
                          is_first_form=is_first_form,
                          show_waitlist=show_waitlist)

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

@app.route('/admin/registration_permissions')
@login_required
def manage_registration_permissions():
    """Admin interface to manage patient registration permissions"""
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    
    # Get all approved users
    users_query = supabase.table('users').select('*').eq('is_approved', True)
    all_users = fetch_all_pages(users_query, debug_name="registration_permissions_users")
    
    # Get users with registration permissions
    permissions_query = supabase.table('registration_permissions').select('*')
    permissions = fetch_all_pages(permissions_query, debug_name="registration_permissions")
    
    # Add user data to each permission
    user_permissions = []
    for permission in permissions:
        user_response = supabase.table('users').select('username, id').eq('id', permission['user_id']).execute()
        if user_response.data:
            permission['user'] = user_response.data[0]
            user_permissions.append(permission)
    
    # Filter out users who already have permissions and admins
    users_without_access = []
    permission_user_ids = {p['user_id'] for p in permissions}
    
    for user in all_users:
        if user['id'] not in permission_user_ids and not user['is_admin']:
            users_without_access.append(user)
    
    return render_template('registration_permissions.html', 
                           user_permissions=user_permissions, 
                           available_users=users_without_access)

@app.route('/admin/registration_permissions/grant', methods=['POST'])
@login_required
def grant_registration_access():
    """Grant registration access to a user"""
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No user selected', 'danger')
        return redirect(url_for('manage_registration_permissions'))
    
    # Check if permission already exists
    check_response = supabase.table('registration_permissions').select('*').eq('user_id', user_id).execute()
    if check_response.data:
        flash('User already has registration access', 'warning')
        return redirect(url_for('manage_registration_permissions'))
    
    # Get user name for logging
    user_response = supabase.table('users').select('username').eq('id', user_id).execute()
    username = user_response.data[0]['username'] if user_response.data else "Unknown user"
    
    # Add permission
    permission = {
        'id': str(uuid.uuid4()),
        'user_id': user_id
    }
    
    supabase.table('registration_permissions').insert(permission).execute()
    
    # Log access grant
    log_activity('grant_access', 'registration_permission', permission['id'], f"Granted registration access to {username}")
    
    flash(f'Registration access granted to {username}', 'success')
    return redirect(url_for('manage_registration_permissions'))

@app.route('/admin/registration_permissions/revoke/<permission_id>', methods=['POST'])
@login_required
def revoke_registration_access(permission_id):
    """Revoke registration access from a user"""
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('index'))
    
    # Get permission details for logging
    permission_response = supabase.table('registration_permissions').select('*').eq('id', permission_id).execute()
    if permission_response.data:
        user_id = permission_response.data[0]['user_id']
        user_response = supabase.table('users').select('username').eq('id', user_id).execute()
        username = user_response.data[0]['username'] if user_response.data else "Unknown user"
        
        # Log revoke action
        log_activity('revoke_access', 'registration_permission', permission_id, f"Revoked registration access from {username}")
        
        # Delete permission
        supabase.table('registration_permissions').delete().eq('id', permission_id).execute()
        flash(f'Registration access revoked from {username}', 'success')
    else:
        flash('Permission not found', 'danger')
    
    return redirect(url_for('manage_registration_permissions'))

def evaluate_field_visibility(field, form_data):
    """
    Evaluate whether a field should be visible based on its conditional logic.
    Returns True if the field should be visible, False if it should be hidden.
    Handles both single conditions (backward compatibility) and multiple conditions with AND/OR logic.
    """
    # If field has no condition, it's always visible
    if not field.get('condition'):
        return True
    
    condition = field['condition']
    
    # Handle new format with multiple conditions
    if isinstance(condition, dict) and 'rules' in condition:
        logic = condition.get('logic', 'OR')
        rules = condition.get('rules', [])
        
        if not rules:
            return True
        
        # Evaluate each rule
        rule_results = []
        for rule in rules:
            result = evaluate_single_condition(rule, form_data)
            rule_results.append(result)
        
        # Apply logic
        if logic == 'AND':
            return all(rule_results)
        else:  # OR (default)
            return any(rule_results)
    
    # Handle backward compatibility - single condition format
    else:
        return evaluate_single_condition(condition, form_data)

def evaluate_single_condition(condition, form_data):
    """
    Evaluate a single condition rule.
    """
    dependent_field = condition.get('dependent_field')
    operator = condition.get('operator', 'equals')
    expected_value = condition.get('value', '')
    
    # Safety check for dependent field
    if not dependent_field:
        print(f"Warning: Condition has no dependent_field: {condition}")
        return True
    
    # Get the actual value from form data
    actual_value = form_data.get(dependent_field)
    
    # Handle different data types
    if actual_value is None:
        actual_value = ''
    elif isinstance(actual_value, list):
        # For checkbox fields, convert to comma-separated string
        actual_value = ', '.join(str(v) for v in actual_value if v)
    else:
        actual_value = str(actual_value)
    
    expected_value = str(expected_value)
    
    # Debug logging for conditional logic
    print(f"Evaluating condition: "
          f"dependent_field='{dependent_field}', operator='{operator}', "
          f"expected='{expected_value}', actual='{actual_value}'")
    
    # Evaluate based on operator
    result = False
    if operator == 'equals':
        result = actual_value.lower().strip() == expected_value.lower().strip()
    elif operator == 'not_equals':
        result = actual_value.lower().strip() != expected_value.lower().strip()
    elif operator == 'contains':
        result = expected_value.lower().strip() in actual_value.lower().strip()
    elif operator == 'not_contains':
        result = expected_value.lower().strip() not in actual_value.lower().strip()
    elif operator == 'in_list':
        # Parse comma-separated expected values and check if actual value matches any of them
        expected_values = [val.strip().lower() for val in expected_value.split(',') if val.strip()]
        
        # Handle multiple selected values (like from checkboxes)
        if ',' in actual_value:
            # Multiple values selected - check if ANY selected value is in the expected list
            actual_values = [val.strip().lower() for val in actual_value.split(',') if val.strip()]
            result = any(val in expected_values for val in actual_values)
        else:
            # Single value - check if it's in the expected list
            result = actual_value.lower().strip() in expected_values
    elif operator == 'is_empty':
        result = actual_value.strip() == ''
    elif operator == 'is_not_empty':
        result = actual_value.strip() != ''
    elif operator == 'starts_with':
        result = actual_value.lower().strip().startswith(expected_value.lower().strip())
    elif operator == 'ends_with':
        result = actual_value.lower().strip().endswith(expected_value.lower().strip())
    else:
        # Default to equals for unknown operators
        result = actual_value.lower().strip() == expected_value.lower().strip()
    
    print(f"Condition evaluation result: {result}")
    return result

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
    
    # Get the selected patient ID from the form submission
    patient_id = request.form.get('patient_id')
    if not patient_id:
        flash('Patient ID is required', 'danger')
        return redirect(url_for('view_form', form_id=form_id))
    
    # Collect form data and validate required fields with conditional logic
    form_data = {}
    validation_errors = []
    
    # First pass: collect all form data
    for field in form['fields']:
        field_label = field['label']
        field_value = None
        
        if field['type'] in ['dropdown', 'radio']:
            field_value = request.form.get(field_label)
        elif field['type'] == 'checkbox':
            field_value = request.form.getlist(field_label)
        else:
            field_value = request.form.get(field_label)
        
        form_data[field_label] = field_value
    
    # Second pass: validate required fields only if they should be visible
    for field in form['fields']:
        field_label = field['label']
        field_value = form_data[field_label]
        
        # Check if this field should be visible based on conditional logic
        should_be_visible = evaluate_field_visibility(field, form_data)
        
        # Only validate required fields that should be visible
        if field.get('required', False) and should_be_visible and (field_value is None or field_value == ''):
            validation_errors.append(f"Field '{field_label}' is required")
            print(f"Required field validation failed: {field_label} (visible: {should_be_visible}, value: {field_value})")
        elif field.get('required', False) and not should_be_visible:
            print(f"Skipping required field validation for hidden field: {field_label}")
    
    # If there are validation errors, flash them and redirect back to the form
    if validation_errors:
        for error in validation_errors:
            flash(error, 'danger')
        return redirect(url_for('view_form', form_id=form_id))
    
    # Create submission in form_submissions table
    new_submission = {
        'id': str(uuid.uuid4()),
        'form_id': form_id,
        'patient_id': patient_id,
        'submitted_by': current_user.id,
        'data': form_data
    }
    
    submission_response = supabase.table('form_submissions').insert(new_submission).execute()
    
    # Update the consolidated patient data in the patients table
    # First check if the patient already exists
    patient_response = supabase.table('patients').select('*').eq('patient_id', patient_id).execute()
    
    if patient_response.data:
        # Patient exists, update their data with this form's fields
        patient_record = patient_response.data[0]
        patient_data = patient_record.get('data', {})
        
        # Add the form's data to the patient record
        patient_data[form_id] = form_data
        
        # Update the patient record
        supabase.table('patients').update({'data': patient_data}).eq('patient_id', patient_id).execute()
    else:
        # Patient doesn't exist yet (could be from legacy data)
        # Create a new patient record
        new_patient = {
            'patient_id': patient_id,
            'data': {form_id: form_data}
        }
        supabase.table('patients').insert(new_patient).execute()
    
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
        # Check if is_archived column exists
        try:
            # First try to update with is_archived
            supabase.table('forms').update({'is_archived': True}).eq('id', form_id).execute()
            # Log form archival
            log_activity('archive', 'form', form_id, f"Form title: {form['title']}")
            flash('Form archived successfully')
        except Exception as archive_error:
            # If column doesn't exist, delete the form instead
            print(f"Error archiving form, falling back to delete: {str(archive_error)}")
            
            # Delete form permissions
            supabase.table('form_permissions').delete().eq('form_id', form_id).execute()
            
            # Delete form submissions
            supabase.table('form_submissions').delete().eq('form_id', form_id).execute()
            
            # Log form deletion
            log_activity('delete', 'form', form_id, f"Form title: {form['title']}")
            
            # Delete the form
            supabase.table('forms').delete().eq('id', form_id).execute()
            
            flash('Form deleted successfully')
    except Exception as e:
        flash(f'Error processing form: {str(e)}', 'danger')
    
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Get only projects that the user has access to
    accessible_projects = []
    
    # Get user's project access records
    access_response = supabase.table('user_project_access').select('project_id').eq('user_id', current_user.id).execute()
    
    if access_response.data:
        # Get project IDs that user has access to
        project_ids = [access['project_id'] for access in access_response.data]
        
        if project_ids:
            # Get project details for accessible projects
            projects_response = supabase.table('projects').select('*').in_('id', project_ids).execute()
            accessible_projects = projects_response.data if projects_response.data else []
            
            # Remove camp_date from fetched projects
            for p in accessible_projects:
                p.pop('camp_date', None)
        
    # Get forms that the user has access to
    accessible_forms = []
    
    # Get permissions for this user
    permissions_query = supabase.table('form_permissions').select('*').eq('user_id', current_user.id)
    user_permissions = fetch_all_pages(permissions_query, debug_name=f"user_{current_user.id}_permissions")
    
    if user_permissions:
        for permission in user_permissions:
            # Get form details separately - exclude archived forms
            form_response = supabase.table('forms').select('*').eq('id', permission['form_id']).eq('is_archived', False).execute()
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
    
    # Check if user has registration access
    has_registration_access = False
    registration_response = supabase.table('registration_permissions').select('*').eq('user_id', current_user.id).execute()
    if registration_response.data:
        has_registration_access = True
    
    return render_template('user_dashboard.html', 
                           projects=accessible_projects, 
                           accessible_forms=accessible_forms,
                           has_registration_access=has_registration_access)

@app.route('/programs')
@login_required
def program_list():
    """List all available programs before showing dataset view"""
    # Get all projects
    projects_query = supabase.table('projects').select('*').order('name')
    projects = fetch_all_pages(projects_query, debug_name="program_list_projects")
    
    # Log activity
    log_activity('view', 'programs_list', None, "Viewed programs list for dataset selection")
    
    return render_template('projects_list.html', 
                         projects=projects,
                         is_dataset_view=True)

@app.route('/dataset')
@login_required
def dataset_view():
    # PERFORMANCE FIX: Add quick loading mode for large datasets
    quick_load = request.args.get('quick_load', 'false').lower() == 'true'
    
    # Get pagination parameters
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    
    per_page = 20  # Number of patients per page
    
    # Get filter parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    field_name = request.args.get('field_name')
    field_value = request.args.get('field_value')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    camp_id = request.args.get('camp_id')
    search_term = request.args.get('search', '').strip()  # Get search term
    
    # Handle camp filtering - if camp_id is provided, override start_date and end_date
    selected_camp = None
    if camp_id:
        try:
            camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
            if camp_response.data:
                selected_camp = camp_response.data[0]
                start_date = selected_camp['start_date']
                end_date = selected_camp['end_date']
                print(f"Using camp '{selected_camp['name']}' dates: {start_date} to {end_date}")
        except Exception as e:
            print(f"Error fetching camp details: {str(e)}")
            # If camp lookup fails, continue with original dates
    
    # If no project_id is provided, redirect to program list
    if not project_id:
        return redirect(url_for('program_list'))
    
    # PERFORMANCE FIX: For quick load mode, get count first and show loading page
    if quick_load:
        try:
            # Get quick count of submissions for this project
            count_query = supabase.table('form_submissions').select('id', count='exact')
            if project_id:
                # Get forms for this project first
                forms_query = supabase.table('forms').select('id').eq('project_id', project_id)
                forms_response = forms_query.execute()
                if forms_response.data:
                    form_ids = [form['id'] for form in forms_response.data]
                    count_query = count_query.in_('form_id', form_ids)
            
            # Apply date filters if present
            if start_date:
                count_query = count_query.gte('created_at', start_date)
            if end_date:
                try:
                    end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                    inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
                    count_query = count_query.lt('created_at', inclusive_end_date)
                except ValueError:
                    pass
            
            count_response = count_query.execute()
            total_count = count_response.count if count_response.count else 0
            
            # If large dataset, return loading page with progressive loading
            if total_count > 1000:
                return render_template('dataset_loading.html', 
                                     total_count=total_count,
                                     project_id=project_id,
                                     form_id=form_id,
                                     field_name=field_name,
                                     field_value=field_value,
                                     start_date=start_date,
                                     end_date=end_date,
                                     camp_id=camp_id,
                                     search_term=search_term)
        except Exception as e:
            print(f"Error getting quick count: {str(e)}")
            # Continue with normal loading if quick count fails
    
    # Log dataset view with filters
    log_details = f"Filters - Project: {project_id or 'All'}, Form: {form_id or 'All'}"
    if field_name and field_value:
        log_details += f", Field: {field_name}={field_value}"
    if camp_id and selected_camp:
        log_details += f", Camp: {selected_camp['name']}"
    elif start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    if search_term: # Log search term
        log_details += f", Search: '{search_term}'"
    log_activity('view', 'dataset', None, log_details)
    
    print(f"Dataset view called with project_id: {project_id}, form_id: {form_id}, search: {search_term}")
    
    # 1. Fetch Ordered Forms for field discovery
    # ALWAYS get all forms in the project for proper field discovery and ordering
    # Form filtering will be applied later to patients, not to field discovery
    ordered_forms_data = []
    
    if project_id: # If a project is selected, fetch ALL its forms with proper ordering
        # Get all forms for this project using pagination
        forms_query = supabase.table('forms').select('*').eq('project_id', project_id)
        all_project_forms = fetch_all_pages(forms_query, debug_name=f"dataset_project_{project_id}_forms")
        if all_project_forms:
            # Separate registration forms from other forms
            registration_forms = []
            other_forms = []
            
            for form in all_project_forms:
                if get_form_is_first(form.get('id')):
                    registration_forms.append(form)
                else:
                    other_forms.append(form)
            
            # Sort both lists by creation date (oldest first)
            registration_forms.sort(key=lambda x: x.get('created_at', ''))
            other_forms.sort(key=lambda x: x.get('created_at', ''))
            
            # Combine: registration forms first, then other forms
            ordered_forms_data = registration_forms + other_forms
    elif form_id: # If only form_id is provided without project_id, get that form's project
        # Get the form to find its project, then get all forms in that project
        form_query = supabase.table('forms').select('*, projects(*)').eq('id', form_id)
        form_response = form_query.execute()
        if form_response.data and form_response.data[0].get('project_id'):
            form_project_id = form_response.data[0]['project_id']
            forms_query = supabase.table('forms').select('*').eq('project_id', form_project_id)
            all_project_forms = fetch_all_pages(forms_query, debug_name=f"dataset_form_project_{form_project_id}_forms")
            if all_project_forms:
                # Apply same ordering logic
                registration_forms = []
                other_forms = []
                
                for form in all_project_forms:
                    if get_form_is_first(form.get('id')):
                        registration_forms.append(form)
                    else:
                        other_forms.append(form)
                
                registration_forms.sort(key=lambda x: x.get('created_at', ''))
                other_forms.sort(key=lambda x: x.get('created_at', ''))
                
                ordered_forms_data = registration_forms + other_forms
    else: # Otherwise fetch all forms, ordered by project then creation
        forms_query = supabase.table('forms').select('*').order('project_id', desc=False).order('created_at', desc=False)
        ordered_forms_data = fetch_all_pages(forms_query, debug_name="dataset_all_forms")

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {} # Stores normalized_label -> original_label mapping

    # Track which fields come from first/registration forms for proper display
    registration_form_fields = set()
    
    # ALWAYS include centralized registration fields first, regardless of project forms
    centralized_registration_fields = [
        'Name',
        'Age (Years)', 
        'Gender',
        'Region',
        'District', 
        'Ward',
        'Phone Number'
    ]
    
    for field_label in centralized_registration_fields:
        normalized_label = field_label.lower().strip().replace(' ', '_')
        if normalized_label not in seen_normalized_fields:
            ordered_fields.append(field_label)
            seen_normalized_fields.add(normalized_label)
            field_label_map[normalized_label] = field_label
            registration_form_fields.add(normalized_label)
            print(f"Added centralized registration field: {field_label}")

    for form in ordered_forms_data:
        # Check if this is a registration form and log it
        is_first = get_form_is_first(form.get('id'))
        if is_first:
            print(f"Processing fields from first/registration form: {form.get('id')} - {form.get('title', 'Unknown')}")
        
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
                        # Mark if this field is from a registration form
                        if is_first:
                            registration_form_fields.add(normalized_label)
                            pass  # Added registration field

    # With centralized registration, we no longer need to pull registration fields from other projects

    # 3. Get all submissions based on filters (project or form)
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # With centralized registration, we only need submissions from the selected project

    # Modified query to get submissions - for field discovery, we get ALL project submissions
    # Form filtering will be applied later to patients, not to field discovery
    query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
    
    if submission_form_ids and not form_id: 
        # Only filter by specific forms if no single form is selected AND we have form IDs
        query = query.in_('form_id', submission_form_ids)
    # NOTE: We removed the project filtering here to avoid join issues - will filter at application level
    
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
    
    # Fetch all submissions using pagination to handle large datasets
    submissions = []
    page_size = 1000
    start = 0
    
    while True:
        try:
            page_response = query.range(start, start + page_size - 1).execute()
            page_data = page_response.data
            
            if not page_data:
                print(f"No more data at start={start}, stopping pagination")
                break
                
            submissions.extend(page_data)
            print(f"Fetched page starting at {start}: {len(page_data)} submissions")
            
            # Continue fetching if we got a full page OR if we got exactly 999 (possible Supabase limit)
            if len(page_data) < page_size and len(page_data) != 999:
                print(f"Got {len(page_data)} records (less than {page_size}), stopping pagination")
                break
                
            start += page_size
            
            # CRITICAL FIX: Remove arbitrary safety limit that could cause missing data
            # Use enhanced safety detection
            if start > 500000:  # Only stop at 500K records (10x higher safety margin)
                print(f"Dataset: CRITICAL WARNING - Reached 500,000 records, investigating...")
                if len(page_data) == page_size:
                    print(f"Dataset: Still getting full pages, continuing with caution...")
                    start += page_size
                    continue
                else:
                    print(f"Dataset: Page size reduced, safe to break")
                break
                
        except Exception as e:
            print(f"Error fetching page starting at {start}: {str(e)}")
            break
    
    print(f"Total submissions fetched: {len(submissions)}")
    if submissions:
        print(f"Sample submission forms: {[s.get('form_id') for s in submissions[:5]]}")
    
    # If we got exactly 999 records, try to fetch more directly
    if len(submissions) == 999:
        print("Got exactly 999 records, trying alternative pagination approach...")
        try:
            # Try with a different approach - fetch a large batch directly
            large_batch_query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
            
            if submission_form_ids:
                large_batch_query = large_batch_query.in_('form_id', submission_form_ids)
            elif form_id:
                large_batch_query = large_batch_query.eq('form_id', form_id)
            elif project_id:
                large_batch_query = large_batch_query.eq('forms.project_id', project_id)
                
            # Apply date filters if present
            if start_date:
                large_batch_query = large_batch_query.gte('created_at', start_date)
            if end_date:
                try:
                    end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                    inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
                    large_batch_query = large_batch_query.lt('created_at', inclusive_end_date)
                except ValueError:
                    pass
            
            # Try to get a large batch with limit
            large_batch_response = large_batch_query.limit(10000).execute()
            if large_batch_response.data and len(large_batch_response.data) > len(submissions):
                print(f"Alternative approach found {len(large_batch_response.data)} records vs {len(submissions)}, using larger set")
                submissions = large_batch_response.data
            else:
                print(f"Alternative approach found {len(large_batch_response.data) if large_batch_response.data else 0} records, keeping original")
                
        except Exception as e:
            print(f"Alternative pagination approach failed: {str(e)}")
            print("Using original pagination results")

    # 4. Keep all submissions for field discovery (search filtering moved to later step)
    
    # 5. Group submissions by patient_id to build dataset
    patient_data = {}
    all_data_fields_normalized = set() # Keep track of fields actually in data
    project_form_ids = set() # Keep track of form IDs that belong to the selected project
    registration_form_ids = set() # Track registration form IDs

    # If project_id is specified, identify forms that belong to this project
    if project_id:
        project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        if project_forms_response.data:
            project_form_ids = {form['id'] for form in project_forms_response.data}
            print(f"Forms from project {project_id}: {project_form_ids}")
        else:
            print(f"No forms found for project {project_id}")

    processed_patients = 0
    included_patients = 0

    for submission in submissions:
        patient_id = submission['patient_id']
        submission_form_id = submission.get('form_id')
        
        # Check if this is a registration form and track it
        is_registration_form = get_form_is_first(submission_form_id)
        if is_registration_form:
            registration_form_ids.add(submission_form_id)
        
        # Skip processing data fields if this submission is from a different project
        # and we have a project filter active
        should_process_fields = (not project_id) or (not project_form_ids) or (submission_form_id in project_form_ids)
        
        if project_id and submission_form_id:
            print(f"Dataset: Processing submission {submission_form_id} for patient {patient_id}")
            print(f"Dataset: Form in project forms? {submission_form_id in project_form_ids}")
            print(f"Dataset: Should process? {should_process_fields}")
        
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': [],
                'has_project_submissions': False  # Flag to track if patient has submissions in this project
            }
        
        # Always add the submission to track the patient, but only mark as project submission if it belongs to project
        patient_data[patient_id]['submissions'].append(submission)
        
        # Mark as having project submissions only if this submission belongs to the selected project
        if should_process_fields:
            patient_data[patient_id]['has_project_submissions'] = True
            print(f"Dataset: Including submission from form {submission_form_id} for patient {patient_id} in project {project_id}")
        else:
            print(f"Dataset: Excluding submission from form {submission_form_id} for patient {patient_id} - not in project {project_id}")
        
        # Collect all unique field keys from actual data, but only if they belong to the selected project
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                # Ensure field_label_map has original casing even for data-only fields
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
                    
    # SIMPLIFIED: If a project is selected, include patients who have ANY submissions from that project
    # With centralized registration, we don't need complex "first form" logic anymore
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            # Include patients who have submissions from this project
            if data.get('has_project_submissions', False):
                        filtered_patient_data[patient_id] = data
                        included_patients += 1
            else:
                print(f"Filtered out patient {patient_id} because they have no submissions from this project")
            processed_patients += 1
        
        print(f"Included {included_patients} patients with submissions from this project")
        print(f"Filtered out {processed_patients - included_patients} patients with no submissions from this project")
        patient_data = filtered_patient_data

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
    
    # Determine which fields to show in the filter dropdown based on form selection
    fields_for_filter = []
    if form_id:
        # If a specific form is selected, only show fields from that form
        form_fields = []
        for form in ordered_forms_data:
            if form['id'] == form_id:
                fields_json = form.get('fields', '[]')
                if isinstance(fields_json, str):
                    try:
                        parsed_fields = json.loads(fields_json)
                        form_fields = [field.get('label') for field in parsed_fields 
                                     if isinstance(field, dict) and 'label' in field]
                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse fields for selected form {form_id}")
                elif isinstance(fields_json, list):
                    form_fields = [field.get('label') for field in fields_json 
                                 if isinstance(field, dict) and 'label' in field]
                break
        fields_for_filter = form_fields
    else:
        # If no specific form selected, show all fields
        fields_for_filter = final_ordered_fields
    
    # 9. Pre-process patient data to merge values using normalized keys
    for patient_id, data in patient_data.items():
        merged_data = {}
        # Keep track of the latest submission date for each field
        last_updated = {} 
        
        # Get registration data from centralized patients table
        registration_data = {}
        
        # PERFORMANCE FIX: Skip individual patient lookup here - will be done in batch later
        # Individual queries moved to batch optimization below
        for submission in data['submissions']:
            submission_form_id = submission.get('form_id')
            if submission_form_id and get_form_is_first(submission_form_id) and submission.get('data'):
                submission_date = submission.get('created_at', '')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in registration_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        registration_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date

        # Sort submissions by date (newest first) to prioritize recent data
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        # First add registration data to merged_data to prioritize it
        # This ensures registration data is preserved and appears first in the data table
        for normalized_key, value in registration_data.items():
            merged_data[normalized_key] = value
        
        # Then add data from regular submissions in this project
        for submission in sorted_submissions:
            if submission.get('data'):
                submission_date = submission.get('created_at')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    # Only add/update if this submission is newer or the key hasn't been seen
                    # But don't overwrite registration data
                    if normalized_key not in merged_data or (
                            normalized_key not in registration_form_fields and  # Skip if it's a registration field
                            submission_date and submission_date > last_updated.get(normalized_key, '')
                        ):
                        merged_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
        
        data['merged_data'] = merged_data

    # PERFORMANCE FIX: Batch fetch registration data for all patients and merge
    print(f"Dataset: Fetching centralized registration data for {len(patient_data)} patients")
    patient_ids = list(patient_data.keys())
    if patient_ids:
        try:
            # CRITICAL FIX: Use chunked batch processing to avoid Supabase query limits
            registration_lookup = {}
            chunk_size = 100  # Smaller chunks to avoid Supabase limits
            total_chunks = (len(patient_ids) + chunk_size - 1) // chunk_size
            
            print(f"Dataset: Fetching registration data in {total_chunks} chunks for {len(patient_ids)} patients")
            
            for i in range(0, len(patient_ids), chunk_size):
                chunk = patient_ids[i:i + chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                try:
                    batch_response = supabase.table('patients')\
                        .select('patient_id, data, created_at')\
                        .in_('patient_id', chunk)\
                        .execute()
                    
                    chunk_count = 0
                    for patient_record in batch_response.data:
                        patient_id = patient_record.get('patient_id')
                        if patient_id and patient_record.get('data', {}).get('registration'):
                            registration_lookup[patient_id] = {
                                'registration': patient_record['data']['registration'],
                                'created_at': patient_record.get('created_at', '')
                            }
                            chunk_count += 1
                    
                    print(f"Dataset: Chunk {chunk_num}/{total_chunks}: {chunk_count} registration records found")
                    
                except Exception as chunk_error:
                    print(f"Dataset: Error fetching chunk {chunk_num}: {str(chunk_error)}")
                    continue
            
            print(f"Dataset: TOTAL registration data fetched: {len(registration_lookup)} patients")
            
            # Now merge registration data with existing patient data - registration takes priority
            for patient_id, data in patient_data.items():
                if patient_id in registration_lookup:
                    registration_data = registration_lookup[patient_id]['registration']
                    patient_created_at = registration_lookup[patient_id]['created_at']
                    
                    # Convert registration data to normalized keys and merge - registration takes priority
                    for key, value in registration_data.items():
                        normalized_key = key.lower().strip().replace(' ', '_')
                        # Registration data takes priority over form data
                        data['merged_data'][normalized_key] = value
                        
        except Exception as e:
            print(f"Dataset: Error batch fetching registration data: {str(e)}")
            # Continue without registration data if batch fails

    # 10. Get data for filter dropdowns
    # Get all projects
    projects_query = supabase.table('projects').select('*')
    all_projects = fetch_all_pages(projects_query, debug_name="dataset_all_projects")
    
    # Get all camps for filter dropdown
    camps_data = fetch_all_pages(
        supabase.table('camps').select('*').order('start_date', desc=True),
        debug_name="camps_for_dataset_filter"
    )
    
    # Get the selected project name if a project is selected
    selected_project_name = None
    if project_id:
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            selected_project_name = project_response.data[0]['name']

    # Get forms for filter dropdown (can reuse ordered_forms_data if appropriate or fetch all)
    # Only include forms that belong to the selected project if a project is selected
    all_forms_response = supabase.table('forms').select('*')
    if project_id:
        all_forms_response = all_forms_response.eq('project_id', project_id)
    all_forms_response = all_forms_response.order('project_id').order('title').execute()
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

    # 10.5. Apply form filtering to patients (after field discovery, preserve field structure)
    # Only apply form filtering if:
    # 1. A specific form_id is provided AND
    # 2. We're not just viewing project-level data (user explicitly selected a form)
    if form_id and form_id.strip():
        print(f"Applying form filter for form_id: {form_id}")
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            # Check if this patient has submissions from the selected form
            has_form_submission = any(
                submission.get('form_id') == form_id 
                for submission in data.get('submissions', [])
            )
            if has_form_submission:
                filtered_patient_data[patient_id] = data
        
        patient_data = filtered_patient_data
        print(f"After form filtering: {len(patient_data)} patients remain (have submissions from selected form)")
    else:
        # No form filtering - show all patients from the project
        if project_id:
            print(f"No form filter applied - showing all {len(patient_data)} patients from project {project_id}")
        else:
            print(f"No filters applied - showing all {len(patient_data)} patients")

    # 10.6. Apply search filtering to patients (after field discovery, before final output)
    if search_term:
        try:
            matching_patient_ids = set()
            search_lower = search_term.lower()
            
            # ENHANCED SEARCH: First search in centralized registration data
            print(f"Searching centralized registration data for: '{search_term}'")
            try:
                # Get all patient IDs that currently exist in our patient_data
                current_patient_ids = list(patient_data.keys())
                
                if current_patient_ids:
                    # Search through centralized registration data for these patients
                    patients_query = supabase.table('patients').select('patient_id, data').in_('patient_id', current_patient_ids)
                    patients_response = patients_query.execute()
                    
                    if patients_response.data:
                        for patient_record in patients_response.data:
                            patient_id = patient_record.get('patient_id')
                            
                            # Check patient_id first
                            if search_lower in str(patient_id).lower():
                                matching_patient_ids.add(patient_id)
                                continue
                            
                            # Search in centralized registration data
                            patient_data_record = patient_record.get('data', {})
                            registration_data = patient_data_record.get('registration', {})
                            
                            if isinstance(registration_data, dict):
                                match_found = False
                                for value in registration_data.values():
                                    if isinstance(value, list):
                                        if any(search_lower in str(item).lower() for item in value if item is not None):
                                            match_found = True
                                            break
                                    elif value is not None and search_lower in str(value).lower():
                                        match_found = True
                                        break
                                
                                if match_found:
                                    matching_patient_ids.add(patient_id)
                        
                        print(f"Found {len(matching_patient_ids)} patients with matches in centralized registration data")
                        
            except Exception as e:
                print(f"Error searching centralized registration data: {str(e)}")
            
            # Second pass: search in each patient's merged submission data
            for patient_id, data in patient_data.items():
                # Skip if already found in registration data
                if patient_id in matching_patient_ids:
                    continue
                
                # Check patient_id first (in case it wasn't found in centralized data)
                if search_lower in str(patient_id).lower():
                    matching_patient_ids.add(patient_id)
                    continue 
                
                # Search in merged submission data
                merged_data = data.get('merged_data', {})
                if isinstance(merged_data, dict):
                    match_found = False
                    for value in merged_data.values():
                        if isinstance(value, list):
                            if any(search_lower in str(item).lower() for item in value if item is not None):
                                match_found = True
                                break
                        elif value is not None and search_lower in str(value).lower():
                            match_found = True
                            break
                    
                    if match_found:
                        matching_patient_ids.add(patient_id)
            
            # Filter patient_data to only include matching patients
            filtered_patient_data = {}
            for patient_id, data in patient_data.items():
                if patient_id in matching_patient_ids:
                    filtered_patient_data[patient_id] = data
            
            patient_data = filtered_patient_data
            print(f"Found {len(matching_patient_ids)} patients with matches for '{search_term}'")
            print(f"After search filtering: {len(patient_data)} patients remain")
        except Exception as e:
            print(f"Error during search filtering: {str(e)}")
            # If search fails, fall back to using all patients
            print(f"Search failed, keeping all {len(patient_data)} patients")

    # 11. Convert patient_data dictionary to patient_data_list for the template
    # Respect the proper field ordering established in final_ordered_fields
    patient_data_list = []
    for patient_id, data in patient_data.items():
        if 'merged_data' not in data:
            continue
            
        # Start with patient ID
        patient_row = {'patient_id': patient_id}
        
        # Add all fields in their proper order (final_ordered_fields already has correct ordering)
        for field in final_ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
            else:
                # Add empty value for fields that don't have data
                patient_row[field] = ''
        
        patient_data_list.append(patient_row)

    # 12. Apply pagination to patient_data_list
    total_patients = len(patient_data_list)
    total_pages = (total_patients + per_page - 1) // per_page  # Ceiling division
    
    # Calculate pagination bounds
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_patient_list = patient_data_list[start_index:end_index]
    
    # Calculate pagination controls
    has_prev = page > 1
    has_next = page < total_pages
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None
    
    # Generate page numbers for pagination nav (show 5 pages max)
    max_pages_to_show = 5
    start_page = max(1, page - max_pages_to_show // 2)
    end_page = min(total_pages, start_page + max_pages_to_show - 1)
    
    # Adjust start_page if we're near the end
    if end_page - start_page < max_pages_to_show - 1:
        start_page = max(1, end_page - max_pages_to_show + 1)
    
    page_numbers = list(range(start_page, end_page + 1))

    return render_template('dataset_view.html',
                         patient_data=patient_data,
                         patient_data_list=paginated_patient_list,  # Use paginated list
                         # Pass the final ordered list of field labels
                         ordered_fields=final_ordered_fields, 
                         all_fields_for_filter=fields_for_filter,  # Add this missing parameter
                         projects=all_projects,
                         forms=filter_forms, # Use all forms for the filter dropdown
                         camps=camps_data,  # Add camps for filter dropdown
                         field_values=sorted(list(field_values)),
                         selected_project=project_id,
                         selected_project_name=selected_project_name,  # Add this parameter
                         selected_form=form_id,
                         selected_field=field_name,
                         selected_value=field_value,
                         selected_camp=camp_id,
                         selected_camp_name=selected_camp['name'] if selected_camp else None,
                         start_date=start_date,
                         end_date=end_date,
                         search_term=search_term,
                         # Pagination variables
                         current_page=page,
                         total_pages=total_pages,
                         total_patients=total_patients,
                         per_page=per_page,
                         has_prev=has_prev,
                         has_next=has_next,
                         prev_num=prev_num,
                         next_num=next_num,
                         page_numbers=page_numbers,
                         start_index=start_index + 1,  # 1-based for display
                         end_index=min(end_index, total_patients))

@app.route('/api/dataset/progressive/<project_id>')
@login_required
def get_dataset_progressive(project_id):
    """PERFORMANCE FIX: Progressive loading API for large datasets"""
    try:
        # Get pagination parameters
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', 100))
        
        # Get filter parameters
        form_id = request.args.get('form_id')
        field_name = request.args.get('field_name')
        field_value = request.args.get('field_value')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        search_term = request.args.get('search', '').strip()
        
        # Quick validation
        if limit > 500:  # Prevent too large chunks
            limit = 500
            
        print(f"Progressive API: Fetching {limit} records starting at offset {offset} for project {project_id}")
        
        # Build query efficiently - only get essential fields
        query = supabase.table('form_submissions').select('patient_id, data, created_at, form_id')
        
        # Get forms for this project
        forms_query = supabase.table('forms').select('id').eq('project_id', project_id)
        forms_response = forms_query.execute()
        if forms_response.data:
            form_ids = [form['id'] for form in forms_response.data]
            query = query.in_('form_id', form_ids)
        else:
            return jsonify({'data': [], 'has_more': False, 'total_fetched': 0})
        
        # Apply filters
        if form_id:
            query = query.eq('form_id', form_id)
        if start_date:
            query = query.gte('created_at', start_date)
        if end_date:
            try:
                end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
                query = query.lt('created_at', inclusive_end_date)
            except ValueError:
                pass
        
        # Get page of data
        query = query.order('created_at', desc=True).range(offset, offset + limit - 1)
        response = query.execute()
        
        submissions = response.data if response.data else []
        
        # Quick patient processing for this chunk
        patient_data = {}
        for submission in submissions:
            patient_id = submission['patient_id']
            if patient_id not in patient_data:
                patient_data[patient_id] = {
                    'patient_id': patient_id,
                    'data': {},
                    'latest_date': submission.get('created_at')
                }
            patient_data[patient_id]['data'].update(submission['data'])
        
        # Convert to simple list format
        result_data = []
        for patient_id, data in patient_data.items():
            patient_row = {'patient_id': patient_id}
            # Add basic fields that are commonly needed
            for key, value in data['data'].items():
                if key.lower() in ['name', 'age', 'gender', 'phone']:
                    patient_row[key] = value
            result_data.append(patient_row)
        
        # Determine if there's more data
        has_more = len(submissions) == limit
        
        return jsonify({
            'data': result_data,
            'has_more': has_more,
            'total_fetched': offset + len(submissions),
            'chunk_size': len(result_data)
        })
        
    except Exception as e:
        print(f"Progressive API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
        
        # First, get registration data from centralized patients table
        patient_response = supabase.table('patients').select('*').eq('patient_id', patient_id).execute()
        registration_data = None
        
        if patient_response.data:
            patient_record = patient_response.data[0]
            registration_data = patient_record.get('data', {})
            print(f"Found registration data for patient {patient_id}")
        else:
            print(f"No registration data found in patients table for patient {patient_id}")
        
        # Get all form submissions for this patient
        response = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))').eq('patient_id', patient_id).execute()
        
        # If no registration data and no form submissions, patient doesn't exist
        if not registration_data and not response.data:
            print(f"No data found for patient {patient_id}")
            return jsonify({'error': 'Patient not found'}), 404
        
        submissions = response.data if response.data else []
        print(f"Number of form submissions found: {len(submissions)}")
        
        # Step 1: Get ordered forms for this patient - keep original order by creation date
        ordered_forms_data = []
        form_ids = set(sub.get('form_id') for sub in submissions if sub.get('form_id'))
        if form_ids:
            forms_response = supabase.table('forms').select('*').in_('id', list(form_ids)).order('created_at', desc=False).execute()
            if forms_response.data:
                ordered_forms_data = forms_response.data
        
        # Create a mapping of form_id to its position in the ordered_forms_data list
        # This ensures we maintain the order of forms when sorting fields
        form_position_map = {form['id']: idx for idx, form in enumerate(ordered_forms_data)}
        
        # Step 2: Build a structure that tracks fields by form
        form_fields_map = {}  # form_id -> list of fields
        field_to_form_map = {}  # field -> form_id
        field_position_map = {}  # field -> position in its form
        field_label_map = {}  # normalized_key -> original label

        for form in ordered_forms_data:
            form_id = form['id']
            form_fields_map[form_id] = []
            
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

            # Store fields by form and track their positions
            if isinstance(parsed_fields, list):
                for position, field in enumerate(parsed_fields):
                    if isinstance(field, dict) and 'label' in field:
                        label = field['label']
                        normalized_label = label.lower().strip().replace(' ', '_')
                        
                        # Keep track of field's form and position
                        field_to_form_map[normalized_label] = form_id
                        field_position_map[normalized_label] = position
                        field_label_map[normalized_label] = label
                        form_fields_map[form_id].append(normalized_label)
        
        # Step 3: Process submissions to get all field data
        all_fields = set()
        data_by_field = {}
        last_updated = {}
        
        # Sort submissions by date (newest first) to prioritize recent data
        sorted_submissions = sorted(submissions, key=lambda s: s.get('created_at', ''), reverse=True) if submissions else []
        
        for submission in sorted_submissions:
            form_id = submission.get('form_id')
            if submission.get('data') and form_id:
                submission_date = submission.get('created_at')
                print(f"DEBUG: Processing submission from form {form_id}, keys: {list(submission['data'].keys())}")
                
                for key, value in submission['data'].items():
                    print(f"DEBUG: Processing field key: '{key}' (type: {type(key)})")
                    
                    # Skip the raw "registration" field since we show registration data separately
                    if str(key).lower().strip() == 'registration':
                        print(f"DEBUG: Skipping registration field: {key}")
                        continue
                    
                    # Skip form IDs (36 char UUIDs with 4 dashes)    
                    if len(str(key)) == 36 and str(key).count('-') == 4:
                        print(f"DEBUG: Skipping form ID: {key}")
                        continue
                        
                    # Double check - don't add registration or form ID fields to tracking
                    if (str(key).lower().strip() == 'registration' or 
                        (len(str(key)) == 36 and str(key).count('-') == 4)):
                        print(f"DEBUG: Double-check skip for field: {key}")
                        continue
                        
                    normalized_key = key.lower().strip().replace(' ', '_')
                    all_fields.add(normalized_key)
                    
                    # Track which form this field belongs to if not already known
                    if normalized_key not in field_to_form_map:
                        field_to_form_map[normalized_key] = form_id
                        # For fields not in form definition, add to the end of their respective form
                        if form_id in form_fields_map and normalized_key not in form_fields_map[form_id]:
                            form_fields_map[form_id].append(normalized_key)
                    
                    # Store original label
                    if normalized_key not in field_label_map:
                        field_label_map[normalized_key] = key
                    
                    # Only update if this is newer data
                    if normalized_key not in data_by_field or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        data_by_field[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
        
        # Step 4: Create ordered result array
        ordered_data = [
            {"field": "Patient ID", "value": patient_id}
        ]
        
        # Add registration data first if available
        if registration_data:
            print(f"DEBUG: Registration data structure: {registration_data}")
            
            # Extract the nested registration fields if they exist
            actual_registration_fields = registration_data.get('registration', {})
            print(f"DEBUG: Actual registration fields: {actual_registration_fields}")
            
            if actual_registration_fields:
                # Define the order for registration fields to match registration form
                registration_field_order = ['Name', 'Age (Years)', 'Gender', 'Region', 'District', 'Ward', 'Phone Number']
                
                # Add registration fields in specified order
                for field_label in registration_field_order:
                    if field_label in actual_registration_fields and actual_registration_fields[field_label] is not None and actual_registration_fields[field_label] != '':
                        ordered_data.append({
                            "field": field_label,
                            "value": actual_registration_fields[field_label]
                        })
                        print(f"DEBUG: Added registration field {field_label}: {actual_registration_fields[field_label]}")
                
                # Add any additional registration fields not in the standard order
                for field_label, field_value in actual_registration_fields.items():
                    if (field_label not in registration_field_order and 
                        field_value is not None and 
                        field_value != ''):
                        ordered_data.append({
                            "field": field_label,
                            "value": field_value
                        })
                        print(f"DEBUG: Added additional registration field {field_label}: {field_value}")
        
        # Process forms in their original order (by creation date)
        for form in ordered_forms_data:
            form_id = form['id']
            if form_id in form_fields_map:
                # Sort fields within this form by their original position
                form_fields = sorted(
                    form_fields_map[form_id],
                    key=lambda f: field_position_map.get(f, 999)
                )
                
                # Add each field from this form in order
                for normalized_key in form_fields:
                    if normalized_key in data_by_field:
                        original_label = field_label_map.get(normalized_key, normalized_key)
                        
                        # Skip registration field and any field that looks like a form ID
                        if (str(original_label).lower().strip() == 'registration' or 
                            len(str(original_label)) == 36 and str(original_label).count('-') == 4):
                            print(f"DEBUG: Skipping field during display: {original_label}")
                            continue
                            
                        ordered_data.append({
                            "field": original_label,
                            "value": data_by_field[normalized_key]
                        })
        
        # Add any fields not associated with a known form
        unknown_fields = [f for f in all_fields if f not in field_to_form_map]
        for normalized_key in sorted(unknown_fields):
            if normalized_key in data_by_field:
                original_label = field_label_map.get(normalized_key, normalized_key)
                
                # Skip registration field and any field that looks like a form ID
                if (str(original_label).lower().strip() == 'registration' or 
                    len(str(original_label)) == 36 and str(original_label).count('-') == 4):
                    print(f"DEBUG: Skipping unknown field during display: {original_label}")
                    continue
                    
                ordered_data.append({
                    "field": original_label,
                    "value": data_by_field[normalized_key]
                })
        
        return jsonify(ordered_data)
            
    except Exception as e:
        print(f"Error fetching patient data: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/export_dataset')
@login_required
def export_dataset():
    # Get filter parameters
    project_id = request.args.get('project_id')
    form_id = request.args.get('form_id')
    field_name = request.args.get('field_name')
    field_value = request.args.get('field_value')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    camp_id = request.args.get('camp_id')
    search_term = request.args.get('search', '').strip()
    
    # Handle camp filtering - if camp_id is provided, override start_date and end_date
    selected_camp = None
    if camp_id:
        try:
            camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
            if camp_response.data:
                selected_camp = camp_response.data[0]
                start_date = selected_camp['start_date']
                end_date = selected_camp['end_date']
                print(f"Export: Using camp '{selected_camp['name']}' dates: {start_date} to {end_date}")
        except Exception as e:
            print(f"Export: Error fetching camp details: {str(e)}")
            # If camp lookup fails, continue with original dates
    
    print(f"Export dataset called with project_id: {project_id}, form_id: {form_id}, search: {search_term}")
    
    # Log the export action with filter details
    log_details = f"Filters - Project: {project_id or 'All'}, Form: {form_id or 'All'}"
    if field_name and field_value:
        log_details += f", Field: {field_name}={field_value}"
    if camp_id and selected_camp:
        log_details += f", Camp: {selected_camp['name']}"
    elif start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    if search_term:
        log_details += f", Search: '{search_term}'"
    log_activity('export', 'dataset', None, log_details)
    
    # This section replicates the dataset_view function to ensure consistency
    
    # 1. Fetch Ordered Forms relevant to the filters
    ordered_forms_data = []
    forms_query = supabase.table('forms').select('*')
    if project_id:
        # When project_id is provided, export ALL forms in that project (ignore form_id filter)
        forms_query = forms_query.eq('project_id', project_id).order('created_at', desc=False)
        print(f"Export: Fetching ALL forms for project {project_id}")
    elif form_id:
        # Only use form_id filtering when no project_id is specified
        forms_query = forms_query.eq('id', form_id)
        print(f"Export: Fetching specific form {form_id}")
    else:
        forms_query = forms_query.order('project_id', desc=False).order('created_at', desc=False)
        print(f"Export: Fetching all forms from all projects")
    
    ordered_forms_data = fetch_all_pages(forms_query, debug_name="export_forms")

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {}
    registration_form_fields = set()
    
    # ALWAYS include centralized registration fields first, regardless of project forms
    centralized_registration_fields = [
        'Name',
        'Age (Years)', 
        'Gender',
        'Region',
        'District', 
        'Ward',
        'Phone Number'
    ]
    
    for field_label in centralized_registration_fields:
        normalized_label = field_label.lower().strip().replace(' ', '_')
        if normalized_label not in seen_normalized_fields:
            ordered_fields.append(field_label)
            seen_normalized_fields.add(normalized_label)
            field_label_map[normalized_label] = field_label
            registration_form_fields.add(normalized_label)
            print(f"Export: Added centralized registration field: {field_label}")

    for form in ordered_forms_data:
        # Check if this is a registration form
        is_first = get_form_is_first(form.get('id'))
        if is_first:
            print(f"Export: Processing fields from registration form: {form.get('id')} - {form.get('title', 'Unknown')}")
        
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
                    normalized_label = label.lower().strip().replace(' ', '_') 
                    if normalized_label not in seen_normalized_fields:
                        ordered_fields.append(label)
                        seen_normalized_fields.add(normalized_label)
                        field_label_map[normalized_label] = label
                        if is_first:
                            registration_form_fields.add(normalized_label)
    
    # With centralized registration, we no longer need to pull registration fields from other projects
    
    # 3. Get all submissions based on filters
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # With centralized registration, we only need submissions from the selected project

    # Query to get submissions
    query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
    
    if submission_form_ids:
        query = query.in_('form_id', submission_form_ids)
    elif form_id:
        query = query.eq('form_id', form_id)
    elif project_id:
        query = query.eq('forms.project_id', project_id)
        
    # Apply date filters if present
    if start_date:
        query = query.gte('created_at', start_date)
    if end_date:
        try:
            end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
            inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
            query = query.lt('created_at', inclusive_end_date) 
        except ValueError:
             print(f"Invalid end date format: {end_date}")
    
    # PERFORMANCE FIX: Use optimized fetch_all_pages function with progress tracking
    submissions = fetch_all_pages(query, debug_name="export_dataset_submissions")
    
    # PERFORMANCE FIX: Add progress tracking for large exports
    if len(submissions) > 1000:
        print(f"Export: Processing {len(submissions)} submissions for dataset export...")
    
    # If we got exactly 999 records, try to fetch more directly
    if len(submissions) == 999:
        print("Export: Got exactly 999 records, trying alternative pagination approach...")
        try:
            # Try with a different approach - fetch a large batch directly
            large_batch_query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
            
            if submission_form_ids:
                large_batch_query = large_batch_query.in_('form_id', submission_form_ids)
            elif form_id:
                large_batch_query = large_batch_query.eq('form_id', form_id)
            elif project_id:
                large_batch_query = large_batch_query.eq('forms.project_id', project_id)
                
            # Apply date filters if present
            if start_date:
                large_batch_query = large_batch_query.gte('created_at', start_date)
            if end_date:
                try:
                    end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
                    inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
                    large_batch_query = large_batch_query.lt('created_at', inclusive_end_date)
                except ValueError:
                    pass
            
            # Try to get a large batch with limit
            large_batch_response = large_batch_query.limit(10000).execute()
            if large_batch_response.data and len(large_batch_response.data) > len(submissions):
                print(f"Export: Alternative approach found {len(large_batch_response.data)} records vs {len(submissions)}, using larger set")
                submissions = large_batch_response.data
            else:
                print(f"Export: Alternative approach found {len(large_batch_response.data) if large_batch_response.data else 0} records, keeping original")
                
        except Exception as e:
            print(f"Export: Alternative pagination approach failed: {str(e)}")
            print("Export: Using original pagination results")

    # 4. Keep all submissions for field discovery (search filtering moved to later step)
    
    # 5. Group submissions by patient_id
    patient_data = {}
    all_data_fields_normalized = set()
    project_form_ids = set()
    registration_form_ids = set()

    if project_id:
        project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        if project_forms_response.data:
            project_form_ids = {form['id'] for form in project_forms_response.data}
            print(f"Export: Forms from project {project_id}: {project_form_ids}")

    for submission in submissions:
        patient_id = submission['patient_id']
        submission_form_id = submission.get('form_id')
        
        # Check if this is a registration form and track it
        is_registration_form = get_form_is_first(submission_form_id)
        if is_registration_form:
            registration_form_ids.add(submission_form_id)
        
        should_process_fields = (not project_id) or (not project_form_ids) or (submission_form_id in project_form_ids)
        
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': [],
                'has_project_submissions': False
            }
        
        # Only include submissions that belong to the selected project (or if no project filter)
        if should_process_fields:
            patient_data[patient_id]['submissions'].append(submission)
            patient_data[patient_id]['has_project_submissions'] = True
            print(f"Export: Including submission from form {submission_form_id} for patient {patient_id} in project {project_id}")
        else:
            print(f"Export: Excluding submission from form {submission_form_id} for patient {patient_id} - not in project {project_id}")
        
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
                    
    # SIMPLIFIED: Include patients who have ANY submissions from this project
    # With centralized registration, we don't need complex "first form" logic anymore
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            # Include patients who have submissions from this project
            if data.get('has_project_submissions', False):
                filtered_patient_data[patient_id] = data
            else:
                print(f"Export: Filtered out patient {patient_id} because they have no submissions from this project")
        
        print(f"Export: Included {len(filtered_patient_data)} patients with submissions from this project")
        print(f"Export: Filtered out {len(patient_data) - len(filtered_patient_data)} patients with no submissions from this project")
        patient_data = filtered_patient_data

    # 6. Apply field value filtering (if specified)
    if field_name and field_value:
        filtered_patient_data = {}
        normalized_filter_field = field_name.lower().strip().replace(' ', '_')
        filter_value_lower = str(field_value).lower().strip()

        for patient_id, data in patient_data.items():
            found_match = False
            for submission in data['submissions']:
                if submission.get('data'):
                    if normalized_filter_field in submission['data']:
                        value = submission['data'][normalized_filter_field]
                        if isinstance(value, list):
                             if any(filter_value_lower == str(item).lower().strip() for item in value):
                                 found_match = True
                                 break
                        elif str(value).lower().strip() == filter_value_lower:
                            found_match = True
                            break
            if found_match:
                filtered_patient_data[patient_id] = data
        patient_data = filtered_patient_data
        print(f"Export: Found {len(patient_data)} patients after field filtering")

    # 7. Identify Extra Fields
    extra_normalized_fields = all_data_fields_normalized - seen_normalized_fields
    extra_field_labels = sorted([field_label_map[norm_key] for norm_key in extra_normalized_fields if norm_key in field_label_map])
    
    # 8. Combine ordered fields with extra fields
    final_ordered_fields = ordered_fields + extra_field_labels
    
    # PERFORMANCE FIX: Batch fetch all patient registration data before processing
    print(f"Export: Batch fetching centralized registration data for {len(patient_data)} patients")
    patient_ids = list(patient_data.keys())
    registration_lookup = {}
    
    if patient_ids:
        try:
            # CRITICAL FIX: Use chunked batch processing to avoid Supabase query limits
            chunk_size = 100  # Smaller chunks to avoid Supabase limits
            total_chunks = (len(patient_ids) + chunk_size - 1) // chunk_size
            
            print(f"Export: Fetching registration data in {total_chunks} chunks for {len(patient_ids)} patients")
            
            for i in range(0, len(patient_ids), chunk_size):
                chunk = patient_ids[i:i + chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                try:
                    batch_response = supabase.table('patients')\
                        .select('patient_id, data, created_at')\
                        .in_('patient_id', chunk)\
                        .execute()
                    
                    chunk_count = 0
                    for patient_record in batch_response.data:
                        patient_id = patient_record.get('patient_id')
                        if patient_id and patient_record.get('data', {}).get('registration'):
                            registration_lookup[patient_id] = {
                                'registration': patient_record['data']['registration'],
                                'created_at': patient_record.get('created_at', '')
                            }
                            chunk_count += 1
                    
                    print(f"Export: Chunk {chunk_num}/{total_chunks}: {chunk_count} registration records found")
                    
                except Exception as chunk_error:
                    print(f"Export: Error fetching chunk {chunk_num}: {str(chunk_error)}")
                    continue
            
            print(f"Export: TOTAL registration data fetched: {len(registration_lookup)} patients")
            

            
        except Exception as e:
            print(f"Export: Error batch fetching registration data: {str(e)}")
            # Continue without registration data if batch fails

    # 9. Pre-process patient data to merge values
    for patient_id, data in patient_data.items():
        merged_data = {}
        last_updated = {} 
        
        # Get registration data from batch lookup
        registration_data = {}
        
        if patient_id in registration_lookup:
            patient_registration = registration_lookup[patient_id]['registration']
            patient_created_at = registration_lookup[patient_id]['created_at']
            
            # Convert registration data to normalized keys
            for key, value in patient_registration.items():
                normalized_key = key.lower().strip().replace(' ', '_')
                registration_data[normalized_key] = value
                if patient_created_at:
                    last_updated[normalized_key] = patient_created_at
        for submission in data['submissions']:
            submission_form_id = submission.get('form_id')
            if submission_form_id and get_form_is_first(submission_form_id) and submission.get('data'):
                form_title = submission.get('forms', {}).get('title', 'Unknown')
                submission_date = submission.get('created_at', '')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in registration_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        registration_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date

        # Sort submissions by date (newest first)
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        # Add registration data first
        for normalized_key, value in registration_data.items():
            merged_data[normalized_key] = value
        
        # Then add data from other submissions
        for submission in sorted_submissions:
            if submission.get('data'):
                submission_date = submission.get('created_at')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in merged_data or (
                            normalized_key not in registration_form_fields and
                            submission_date and submission_date > last_updated.get(normalized_key, '')
                        ):
                        merged_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
        
        data['merged_data'] = merged_data

    # 9.4. Apply form filtering to patients (after field discovery, preserve field structure)
    # Only apply form filtering if:
    # 1. A specific form_id is provided AND
    # 2. We're not just viewing project-level data (user explicitly selected a form)
    if form_id and form_id.strip():
        print(f"Applying form filter for form_id: {form_id}")
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            # Check if this patient has submissions from the selected form
            has_form_submission = any(
                submission.get('form_id') == form_id 
                for submission in data.get('submissions', [])
            )
            if has_form_submission:
                filtered_patient_data[patient_id] = data
        
        patient_data = filtered_patient_data
        print(f"After form filtering: {len(patient_data)} patients remain (have submissions from selected form)")
    else:
        # No form filtering - show all patients from the project
        if project_id:
            print(f"No form filter applied - showing all {len(patient_data)} patients from project {project_id}")
        else:
            print(f"No filters applied - showing all {len(patient_data)} patients")

    # 9.5. Apply search filtering to patients (after field discovery, before final export)
    if search_term:
        try:
            matching_patient_ids = set()
            search_lower = search_term.lower()
            
            # ENHANCED SEARCH: First search in centralized registration data
            print(f"Export: Searching centralized registration data for: '{search_term}'")
            try:
                # Get all patient IDs that currently exist in our patient_data
                current_patient_ids = list(patient_data.keys())
                
                if current_patient_ids:
                    # Search through centralized registration data for these patients
                    patients_query = supabase.table('patients').select('patient_id, data').in_('patient_id', current_patient_ids)
                    patients_response = patients_query.execute()
                    
                    if patients_response.data:
                        for patient_record in patients_response.data:
                            patient_id = patient_record.get('patient_id')
                            
                            # Check patient_id first
                            if search_lower in str(patient_id).lower():
                                matching_patient_ids.add(patient_id)
                                continue
                            
                            # Search in centralized registration data
                            patient_data_record = patient_record.get('data', {})
                            registration_data = patient_data_record.get('registration', {})
                            
                            if isinstance(registration_data, dict):
                                match_found = False
                                for value in registration_data.values():
                                    if isinstance(value, list):
                                        if any(search_lower in str(item).lower() for item in value if item is not None):
                                            match_found = True
                                            break
                                    elif value is not None and search_lower in str(value).lower():
                                        match_found = True
                                        break
                                
                                if match_found:
                                    matching_patient_ids.add(patient_id)
                        
                        print(f"Export: Found {len(matching_patient_ids)} patients with matches in centralized registration data")
                        
            except Exception as e:
                print(f"Export: Error searching centralized registration data: {str(e)}")
            
            # Second pass: search in each patient's merged submission data
            for patient_id, data in patient_data.items():
                # Skip if already found in registration data
                if patient_id in matching_patient_ids:
                    continue
                
                # Check patient_id first (in case it wasn't found in centralized data)
                if search_lower in str(patient_id).lower():
                    matching_patient_ids.add(patient_id)
                    continue 
                
                # Search in merged submission data
                merged_data = data.get('merged_data', {})
                if isinstance(merged_data, dict):
                    match_found = False
                    for value in merged_data.values():
                        if isinstance(value, list):
                            if any(search_lower in str(item).lower() for item in value if item is not None):
                                match_found = True
                                break
                        elif value is not None and search_lower in str(value).lower():
                            match_found = True
                            break
                    
                    if match_found:
                        matching_patient_ids.add(patient_id)
            
            # Filter patient_data to only include matching patients
            filtered_patient_data = {}
            for patient_id, data in patient_data.items():
                if patient_id in matching_patient_ids:
                    filtered_patient_data[patient_id] = data
            
            patient_data = filtered_patient_data
            print(f"Export: Found {len(matching_patient_ids)} patients with matches for '{search_term}'")
            print(f"Export: After search filtering: {len(patient_data)} patients remain")
        except Exception as e:
            print(f"Export: Error during search filtering: {str(e)}")
            # If search fails, fall back to using all patients
            print(f"Export: Search failed, keeping all {len(patient_data)} patients")

    # 10. Convert patient_data dictionary to list for export
    # Respect the proper field ordering established in final_ordered_fields
    patient_data_list = []
    for patient_id, data in patient_data.items():
        if 'merged_data' not in data:
            continue
            
        # Start with patient ID
        patient_row = {'patient_id': patient_id}
        
        # Add all fields in their proper order (final_ordered_fields already has correct ordering)
        for field in final_ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
            else:
                # Add empty value for fields that don't have data
                patient_row[field] = ''
        
        patient_data_list.append(patient_row)
    
    # Create DataFrame from the exact same structure used for the web view
    df = pd.DataFrame(patient_data_list)
    
    # Create Excel file in memory
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Dataset', index=False)
        
        # Auto-adjust columns' width
        worksheet = writer.sheets['Dataset']
        for i, col in enumerate(df.columns):
            # Handle empty dataframes
            if df.empty:
                max_len = len(str(col)) + 2
            else:
                # Get the maximum length of the column contents
                max_len = max(
                    df[col].astype(str).apply(len).max(),
                    len(str(col))
                ) + 2
            worksheet.set_column(i, i, max_len)
    
    output.seek(0)
    
    # Generate a filename based on the filters
    filename = 'dataset'
    if project_id:
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            project_name = project_response.data[0]['name']
            filename = f"{project_name}_dataset"
    
    # Only add form name to filename when filtering by specific form (no project_id)
    if form_id and not project_id:
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
        # Query all projects, ordering by creation date, using pagination
        projects = fetch_all_pages(supabase.table('projects').select('*').order('created_at', desc=True), debug_name="projects_list")
        
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
        flash('You do not have permission to view this page', 'danger')
        return redirect(url_for('index'))
    
    # Get page number from query string
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    
    # Set records per page and calculate offset
    per_page = 15
    offset = (page - 1) * per_page
    
    # Get total count for pagination
    count_response = supabase.table('log_activities').select('id', count='exact').execute()
    total_records = count_response.count if hasattr(count_response, 'count') else 0
    total_pages = (total_records + per_page - 1) // per_page
    
    # Pagination controls
    has_prev = page > 1
    has_next = page < total_pages
    
    # Get logs for current page
    response = supabase.table('log_activities').select('*').order('created_at', desc=True).range(offset, offset + per_page - 1).execute()
    logs = response.data if response.data else []
    
    # Convert UTC timestamps to EAT
    for log in logs:
        if log.get('created_at'):
            log['created_at_eat'] = utc_to_eat(log['created_at'])
        else:
            log['created_at_eat'] = None
    
    return render_template('activity_logs.html',
                          logs=logs,
                          page=page,
                          total_pages=total_pages,
                          has_prev=has_prev,
                          has_next=has_next)

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
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=300)  # Increased DPI for better quality
    buf.seek(0)
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)  # Close figure to free memory
    return f"data:image/png;base64,{img_str}"  # Add proper data URL format prefix

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
    """
    Prepare dataset for analytics by directly using the same dataset export logic.
    This ensures that analytics and exports will always show identical data.
    """
    # Return empty dataframe if no project is selected
    if not project_id:
        return pd.DataFrame()
    
    # This directly reuses the dataset_view logic to get the exact same data as shown in the view
    # and exported to Excel
    
    # 1. Fetch Ordered Forms relevant to the filters
    ordered_forms_data = []
    forms_query = supabase.table('forms').select('*')
    if project_id:
        # When project_id is provided, export ALL forms in that project (ignore form_id filter)
        forms_query = forms_query.eq('project_id', project_id).order('created_at', desc=False)
        print(f"Export: Fetching ALL forms for project {project_id}")
    elif form_id:
        # Only use form_id filtering when no project_id is specified
        forms_query = forms_query.eq('id', form_id)
        print(f"Export: Fetching specific form {form_id}")
    else:
        forms_query = forms_query.order('project_id', desc=False).order('created_at', desc=False)
        print(f"Export: Fetching all forms from all projects")
    
    forms_response = forms_query.execute()
    if forms_response.data:
        ordered_forms_data = forms_response.data

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {}
    registration_form_fields = set()
    
    # ALWAYS include centralized registration fields first, regardless of project forms
    centralized_registration_fields = [
        'Name',
        'Age (Years)', 
        'Gender',
        'Region',
        'District', 
        'Ward',
        'Phone Number'
    ]
    
    for field_label in centralized_registration_fields:
        normalized_label = field_label.lower().strip().replace(' ', '_')
        if normalized_label not in seen_normalized_fields:
            ordered_fields.append(field_label)
            seen_normalized_fields.add(normalized_label)
            field_label_map[normalized_label] = field_label
            registration_form_fields.add(normalized_label)

    for form in ordered_forms_data:
        # Check if this is a registration form
        is_first = get_form_is_first(form.get('id'))
        
        fields_json = form.get('fields', '[]')
        if isinstance(fields_json, str):
            try:
                parsed_fields = json.loads(fields_json)
            except json.JSONDecodeError:
                parsed_fields = []
        elif isinstance(fields_json, list):
            parsed_fields = fields_json
        else:
            parsed_fields = []

        if isinstance(parsed_fields, list):
            for field in parsed_fields:
                if isinstance(field, dict) and 'label' in field:
                    label = field['label']
                    normalized_label = label.lower().strip().replace(' ', '_') 
                    if normalized_label not in seen_normalized_fields:
                        ordered_fields.append(label)
                        seen_normalized_fields.add(normalized_label)
                        field_label_map[normalized_label] = label
                        if is_first:
                            registration_form_fields.add(normalized_label)
    
    # With centralized registration, we no longer need to pull registration fields from other projects
    
    # 3. Get all submissions based on filters
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # With centralized registration, we only need submissions from the selected project

    # PERFORMANCE FIX: Optimize query to fetch only essential fields
    query = supabase.table('form_submissions').select('patient_id, data, created_at, form_id, forms(title, fields, project_id, projects(name))')
    
    if submission_form_ids:
        query = query.in_('form_id', submission_form_ids)
    elif form_id:
        query = query.eq('form_id', form_id)
    elif project_id:
        query = query.eq('forms.project_id', project_id)
        
    # Apply date filters if present
    if start_date:
        query = query.gte('created_at', start_date)
    if end_date:
        try:
            end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
            inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
            query = query.lt('created_at', inclusive_end_date) 
        except ValueError:
            pass
    
    # PERFORMANCE FIX: Use optimized fetch_all_pages function
    submissions = fetch_all_pages(query, debug_name="analytics_submissions")
    
    # PERFORMANCE FIX: Add progress tracking for large analytics datasets
    if len(submissions) > 1000:
        print(f"Analytics: Processing {len(submissions)} submissions for analysis...")

    # 4. Process the submissions into a patient-based dataset
    patient_data = {}
    all_data_fields_normalized = set()
    project_form_ids = set()
    registration_form_ids = set()

    if project_id:
        project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
        if project_forms_response.data:
            project_form_ids = {form['id'] for form in project_forms_response.data}

    for submission in submissions:
        patient_id = submission['patient_id']
        submission_form_id = submission.get('form_id')
        
        # Check if this is a registration form
        is_registration_form = get_form_is_first(submission_form_id)
        if is_registration_form:
            registration_form_ids.add(submission_form_id)
        
        should_process_fields = (not project_id) or (not project_form_ids) or (submission_form_id in project_form_ids)
        
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': [],
                'has_project_submissions': False
            }
        
        # Always add the submission to track the patient, but only mark as project submission if it belongs to project
        patient_data[patient_id]['submissions'].append(submission)
        
        # Mark as having project submissions only if this submission belongs to the selected project
        if should_process_fields:
            patient_data[patient_id]['has_project_submissions'] = True
            print(f"Analytics: Including submission from form {submission_form_id} for patient {patient_id} in project {project_id}")
        else:
            print(f"Analytics: Excluding submission from form {submission_form_id} for patient {patient_id} - not in project {project_id}")
        
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
    
    # SIMPLIFIED: Include patients who have ANY submissions from this project
    # With centralized registration, analytics shows patients who participated in the selected program
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            if data.get('has_project_submissions', False):
                filtered_patient_data[patient_id] = data
        
        print(f"Analytics: Included {len(filtered_patient_data)} patients with submissions from this project")
        print(f"Analytics: Filtered out {len(patient_data) - len(filtered_patient_data)} patients with no submissions from this project")
        patient_data = filtered_patient_data

    # Find extra fields in submissions that weren't in form definitions
    extra_normalized_fields = all_data_fields_normalized - seen_normalized_fields
    extra_field_labels = sorted([field_label_map[norm_key] for norm_key in extra_normalized_fields if norm_key in field_label_map])
    
    # Combine ordered fields with extra fields
    final_ordered_fields = ordered_fields + extra_field_labels
    
    # Pre-process patient data to merge values
    for patient_id, data in patient_data.items():
        merged_data = {}
        last_updated = {} 
        
        # Get registration data from centralized patients table
        registration_data = {}
        
        # PERFORMANCE FIX: Skip individual patient lookup here - will be done in batch later
        # Individual queries moved to batch optimization below
        for submission in data['submissions']:
            submission_form_id = submission.get('form_id')
            if submission_form_id and get_form_is_first(submission_form_id) and submission.get('data'):
                submission_date = submission.get('created_at', '')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in registration_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        registration_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date

        # Sort submissions by date (newest first)
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        # Add registration data first
        for normalized_key, value in registration_data.items():
            merged_data[normalized_key] = value
        
        # Then add data from other submissions
        for submission in sorted_submissions:
            if submission.get('data'):
                submission_date = submission.get('created_at')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in merged_data or (
                            normalized_key not in registration_form_fields and
                            submission_date and submission_date > last_updated.get(normalized_key, '')
                        ):
                        merged_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
        
        data['merged_data'] = merged_data

    # PERFORMANCE FIX: Batch fetch registration data for all patients before DataFrame creation
    print(f"Analytics: Fetching centralized registration data for {len(patient_data)} patients")
    patient_ids = list(patient_data.keys())
    if patient_ids:
        try:
            # CRITICAL FIX: Use chunked batch processing to avoid Supabase query limits
            registration_lookup = {}
            chunk_size = 100  # Smaller chunks to avoid Supabase limits
            total_chunks = (len(patient_ids) + chunk_size - 1) // chunk_size
            
            print(f"Analytics: Fetching registration data in {total_chunks} chunks for {len(patient_ids)} patients")
            
            for i in range(0, len(patient_ids), chunk_size):
                chunk = patient_ids[i:i + chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                try:
                    batch_response = supabase.table('patients')\
                        .select('patient_id, data, created_at')\
                        .in_('patient_id', chunk)\
                        .execute()
                    
                    chunk_count = 0
                    for patient_record in batch_response.data:
                        patient_id = patient_record.get('patient_id')
                        if patient_id and patient_record.get('data', {}).get('registration'):
                            registration_lookup[patient_id] = {
                                'registration': patient_record['data']['registration'],
                                'created_at': patient_record.get('created_at', '')
                            }
                            chunk_count += 1
                    
                    print(f"Analytics: Chunk {chunk_num}/{total_chunks}: {chunk_count} registration records found")
                    
                except Exception as chunk_error:
                    print(f"Analytics: Error fetching chunk {chunk_num}: {str(chunk_error)}")
                    continue
            
            print(f"Analytics: TOTAL registration data fetched: {len(registration_lookup)} patients")
            
            # Now merge registration data with existing patient data
            for patient_id, data in patient_data.items():
                if patient_id in registration_lookup:
                    registration_data = registration_lookup[patient_id]['registration']
                    patient_created_at = registration_lookup[patient_id]['created_at']
                    
                    # Convert registration data to normalized keys and merge
                    for key, value in registration_data.items():
                        normalized_key = key.lower().strip().replace(' ', '_')
                        # Only add if not already present (form data takes precedence)
                        if normalized_key not in data['merged_data']:
                            data['merged_data'][normalized_key] = value
                        
        except Exception as e:
            print(f"Analytics: Error batch fetching registration data: {str(e)}")
            # Continue without registration data if batch fails

    # Convert patient_data dictionary to list for DataFrame - exactly as in dataset_view
    patient_data_list = []
    for patient_id, data in patient_data.items():
        if 'merged_data' not in data:
            continue
            
        # Start with patient ID
        patient_row = {'patient_id': patient_id}
        
        # Add registration form fields first
        for field in ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key in registration_form_fields and normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
        
        # Add all other fields
        for field in ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key not in registration_form_fields and normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
                
        # Add any extra fields not in ordered_fields
        for field in extra_field_labels:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
        
        patient_data_list.append(patient_row)
    
    # Create DataFrame - this matches exactly what would be exported to Excel from dataset view
    df = pd.DataFrame(patient_data_list)
    
    # Convert potentially numeric columns to numeric type for analytics
    for column in df.columns:
        if df[column].dtype == 'object':  # If it's a string/object type
            # Try to convert to numeric, setting errors='coerce' will convert failures to NaN
            numeric_series = pd.to_numeric(df[column], errors='coerce')
            # If the conversion didn't result in all NaNs, consider it numeric
            if not numeric_series.isna().all():
                # Calculate what percentage of values converted successfully
                success_rate = 1 - (numeric_series.isna().sum() / len(numeric_series))
                # If more than 80% of values converted successfully, treat as numeric
                if success_rate > 0.8:
                    df[column] = numeric_series
    
    return df

def categorize_age(age):
    """Convert numerical age to meaningful age groups"""
    if pd.isna(age):
        return None
    
    try:
        age_num = float(age)
        if age_num <= 5:
            return "Under-fives (0–5)"
        elif age_num <= 12:
            return "School-age children (6–12)"
        elif age_num <= 17:
            return "Adolescents (13–17)"
        elif age_num <= 39:
            return "Young adults (18–39)"
        elif age_num <= 59:
            return "Middle-aged adults (40–59)"
        elif age_num <= 79:
            return "Older adults (60–79)"
        else:
            return "Elderly (80+)"
    except (ValueError, TypeError):
        return None

def get_age_group_order():
    """Get the correct ordinal order for age groups"""
    return [
        "Under-fives (0–5)", 
        "School-age children (6–12)", 
        "Adolescents (13–17)", 
        "Young adults (18–39)", 
        "Middle-aged adults (40–59)", 
        "Older adults (60–79)", 
        "Elderly (80+)"
    ]

def sort_age_groups(df, age_column):
    """Sort a dataframe by age groups in proper ordinal order"""
    age_order = get_age_group_order()
    
    # Create a categorical column with proper ordering
    if age_column in df.columns:
        df[age_column] = pd.Categorical(df[age_column], categories=age_order, ordered=True)
    
    return df

def is_age_field(field_name):
    """Check if a field represents age data"""
    field_lower = field_name.lower()
    return 'age' in field_lower and ('year' in field_lower or 'age' == field_lower.strip())

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
    camp_id = request.args.get('camp_id')
    analysis_type = request.args.get('analysis_type')
    field1 = request.args.get('field1')
    field2 = request.args.get('field2')
    
    # Handle camp filtering - if camp_id is provided, override start_date and end_date
    selected_camp = None
    if camp_id:
        try:
            camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
            if camp_response.data:
                selected_camp = camp_response.data[0]
                start_date = selected_camp['start_date']
                end_date = selected_camp['end_date']
                print(f"Analytics: Using camp '{selected_camp['name']}' dates: {start_date} to {end_date}")
        except Exception as e:
            print(f"Analytics: Error fetching camp details: {str(e)}")
            # If camp lookup fails, continue with original dates
    
    # Get correlation fields (multiple selection)
    correlation_fields = request.args.getlist('correlation_fields[]')
    
    # Get all projects for filter dropdown using pagination
    all_projects = fetch_all_pages(supabase.table('projects').select('*'), debug_name="analytics_projects")
    
    # Get relevant forms based on project selection
    if project_id:
        # Only get forms for the selected project
        forms_query = supabase.table('forms').select('*').eq('project_id', project_id)
        forms = fetch_all_pages(forms_query, debug_name=f"analytics_project_{project_id}_forms")
    else:
        # Get all forms if no project is selected using pagination
        forms = fetch_all_pages(supabase.table('forms').select('*'), debug_name="analytics_all_forms")
    
    # Initialize variables
    df = None
    all_fields = []
    field_types = {}
    plots = []
    stats = None
    title = None
    
    # Only proceed with analysis if project_id is provided
    if project_id:
        # Get project name for the title
        project_name = None
        for project in all_projects:
            if project['id'] == project_id:
                project_name = project['name']
                break
        
        # Get the dataset using the exact same logic as the dataset view
        # This ensures consistency between analytics and the dataset view
        df = prepare_dataset_for_analysis(project_id, form_id, start_date, end_date)
        
        # If dataframe is empty, show message
        if df.empty:
            flash('No data available for the selected program.', 'warning')
        else:
            # Add a note about the data source
            data_source_note = f"Analysis of {len(df)} patients from program: {project_name}"
            if form_id:
                form_name = None
                for form in forms:
                    if form['id'] == form_id:
                        form_name = form['title']
                        break
                if form_name:
                    data_source_note += f", form: {form_name}"
            if start_date or end_date:
                date_range = f" from {start_date}" if start_date else " until"
                if end_date:
                    date_range += f" to {end_date}"
                data_source_note += date_range
            
            # Get all field names from the dataset columns
            # This approach works directly with the column names in the dataset
            excluded_cols = ['patient_id', 'submission_id']
            all_fields = [col for col in df.columns if col not in excluded_cols]
            
            # Determine field types for analysis
            for field in all_fields:
                # First check if this field contains lists (checkbox data)
                contains_lists = False
                try:
                    # Check if any value in this field is a list
                    contains_lists = df[field].apply(lambda x: isinstance(x, list)).any()
                    if contains_lists:
                        field_types[field] = 'checkbox'
                        continue
                except:
                    # If we can't check (e.g., field is empty), assume it's not a list
                    pass
                
                if df[field].dtype == 'object':  # String/categorical
                    # Try to convert to numeric, setting errors='coerce' will convert failures to NaN
                    numeric_series = pd.to_numeric(df[field], errors='coerce')
                    # If the conversion didn't result in all NaNs, consider it numeric
                    if not numeric_series.isna().all():
                        # Calculate what percentage of values converted successfully
                        success_rate = 1 - (numeric_series.isna().sum() / len(numeric_series))
                        # If more than 80% of values converted successfully, treat as numeric
                        if success_rate > 0.8:
                            field_types[field] = 'numeric'
                        else:
                            # Fall back to categorical vs text determination
                            try:
                                unique_count = df[field].nunique()
                                if unique_count <= 15:  # Arbitrary threshold for categorical
                                    field_types[field] = 'categorical'
                                else:
                                    field_types[field] = 'text'
                            except TypeError:
                                # If we get a TypeError (unhashable type like list), convert to string first
                                unique_count = df[field].astype(str).nunique()
                                if unique_count <= 15:
                                    field_types[field] = 'categorical'
                                else:
                                    field_types[field] = 'text'
                    else:
                        # Count unique values to determine if it's categorical
                        try:
                            unique_count = df[field].nunique()
                            if unique_count <= 15:  # Arbitrary threshold for categorical
                                field_types[field] = 'categorical'
                            else:
                                field_types[field] = 'text'
                        except TypeError:
                            # If we get a TypeError (unhashable type like list), convert to string first
                            unique_count = df[field].astype(str).nunique()
                            if unique_count <= 15:
                                field_types[field] = 'categorical'
                            else:
                                field_types[field] = 'text'
                elif np.issubdtype(df[field].dtype, np.number):  # Already numeric
                    field_types[field] = 'numeric'
                else:
                    field_types[field] = 'unknown'
            
            # If analysis fields are specified, perform analysis
            if analysis_type:
                # 1. Summary Statistics for a field
                if analysis_type == 'summary_statistics' and field1:
                    title = f"Summary Statistics for {field1}"
                    
                    # Check if the field exists in the dataset
                    if field1 not in df.columns:
                        stats = f"<div class='alert alert-warning'>Selected field '{field1}' does not exist in the dataset.</div>"
                    else:
                        field1_type = field_types.get(field1, 'unknown')
                        
                        # For checkbox fields (containing lists), show special stats
                        if field1_type == 'checkbox':
                            # Flatten the lists and count unique options
                            all_values = []
                            selection_counts = []  # Track how many options each record selected
                            
                            for values in df[field1].dropna():
                                if isinstance(values, list):
                                    all_values.extend(values)
                                    selection_counts.append(len(values))
                                elif values:  # Handle non-list values if any
                                    all_values.append(values)
                                    selection_counts.append(1)
                                else:
                                    selection_counts.append(0)
                            
                            if all_values:
                                # Count occurrences of each option
                                unique_options = set(all_values)
                                option_counts = {option: all_values.count(option) for option in unique_options}
                                
                                # Create a DataFrame for option counts
                                option_df = pd.DataFrame({'Option': list(option_counts.keys()), 
                                                         'Count': list(option_counts.values())})
                                option_df['Percentage'] = (option_df['Count'] / len(df) * 100).round(2)
                                option_df = option_df.sort_values('Count', ascending=False)
                                
                                # Get selection count statistics
                                selection_stats = pd.Series(selection_counts).describe().to_dict()
                                
                                # Get missing/empty values count
                                empty_count = df[field1].isna().sum() + df[field1].apply(lambda x: isinstance(x, list) and len(x) == 0).sum()
                                
                                stats = f"""
                                <div class='alert alert-info mb-3'>{data_source_note}</div>
                                <div class='alert alert-info'>
                                    <p>Field type: Checkbox (Multiple Selection)</p>
                                    <p>Total records: {len(df)}</p>
                                    <p>Unique options: {len(unique_options)}</p>
                                    <p>Empty selections: {empty_count} ({(empty_count/len(df)*100).round(2)}%)</p>
                                    <p>Average selections per record: {round(selection_stats.get('mean', 0), 2)}</p>
                                    <p>Maximum selections on one record: {int(selection_stats.get('max', 0))}</p>
                                </div>
                                <h5>Option Frequencies:</h5>
                                {option_df.to_html(classes='table table-striped table-hover', index=False)}
                                """
                                
                                # Create visualization
                                if len(option_df) > 15:
                                    plot_data = option_df.head(15)
                                    title_suffix = " (Top 15 Options)"
                                else:
                                    plot_data = option_df
                                    title_suffix = ""
                                
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.barplot(x='Option', y='Count', data=plot_data, ax=ax)
                                ax.set_title(f'Selection Frequency{title_suffix}')
                                plt.xticks(rotation=45, ha='right')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Option Distribution',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Create distribution of selection counts
                                selection_df = pd.DataFrame({'Selections': selection_counts})
                                fig, ax = plt.subplots(figsize=(10, 6))
                                sns.histplot(data=selection_df, x='Selections', discrete=True, ax=ax)
                                ax.set_title('Distribution of Selection Counts')
                                ax.set_xlabel('Number of Options Selected')
                                ax.set_ylabel('Number of Records')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Selection Count Distribution',
                                    'img': fig_to_base64(fig)
                                })
                            else:
                                stats = f"<div class='alert alert-warning'>No data available for this checkbox field.</div>"
                        
                        # For numeric fields, show numeric statistics
                        elif field1_type == 'numeric':
                            # Convert to numeric, handling errors by converting them to NaN
                            numeric_data = pd.to_numeric(df[field1], errors='coerce')
                            # Drop NaN values for statistics
                            numeric_data = numeric_data.dropna()
                            
                            if len(numeric_data) > 0:
                                desc_stats = numeric_data.describe().to_frame().reset_index()
                                desc_stats.columns = ['Statistic', 'Value']
                                # Add missing data information
                                missing_count = df[field1].isna().sum() + (len(df[field1]) - len(numeric_data))
                                missing_row = pd.DataFrame({'Statistic': ['Missing Values'], 'Value': [missing_count]})
                                desc_stats = pd.concat([desc_stats, missing_row], ignore_index=True)
                                
                                # Add data source note
                                stats = f"<div class='alert alert-info mb-3'>{data_source_note}</div>"
                                stats += desc_stats.to_html(classes='table table-striped table-hover', index=False)
                                
                                # Create a histogram for numeric data
                                fig, ax = plt.subplots(figsize=(10, 6))
                                sns.histplot(numeric_data, kde=True, ax=ax)
                                ax.set_title(f'Distribution of {field1}')
                                ax.set_xlabel(field1)
                                ax.set_ylabel('Frequency')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Distribution Histogram',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Create a boxplot for numeric data
                                fig, ax = plt.subplots(figsize=(10, 6))
                                sns.boxplot(x=numeric_data, ax=ax)
                                ax.set_title(f'Boxplot of {field1}')
                                ax.set_xlabel(field1)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Boxplot',
                                    'img': fig_to_base64(fig)
                                })
                            else:
                                stats = "<div class='alert alert-warning'>No valid numeric data available for statistics.</div>"
                        
                        # For categorical fields, show frequency distribution
                        elif field1_type == 'categorical':
                            # Get value counts
                            value_counts = df[field1].value_counts().reset_index()
                            value_counts.columns = ['Value', 'Count']
                            value_counts['Percentage'] = (value_counts['Count'] / value_counts['Count'].sum() * 100).round(2)
                            
                            # Add data source note
                            stats = f"<div class='alert alert-info mb-3'>{data_source_note}</div>"
                            stats += value_counts.to_html(classes='table table-striped table-hover', index=False)
                            
                            # Create a bar chart for categorical data
                            fig, ax = plt.subplots(figsize=(12, 6))
                            sns.barplot(x='Value', y='Count', data=value_counts, ax=ax)
                            ax.set_title(f'Frequency Distribution of {field1}')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Frequency Distribution',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Create a pie chart if fewer than 8 categories
                            if len(value_counts) < 8:
                                fig, ax = plt.subplots(figsize=(8, 8))
                                ax.pie(value_counts['Count'], labels=value_counts['Value'], autopct='%1.1f%%')
                                ax.set_title(f'Distribution of {field1}')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Pie Chart',
                                    'img': fig_to_base64(fig)
                                })
                        
                        # For text fields, show basic stats
                        else:
                            try:
                                # Count unique values
                                unique_count = df[field1].nunique()
                                # Count non-missing values
                                non_missing = df[field1].count()
                                # Get most common values
                                most_common = df[field1].value_counts().head(10).reset_index()
                                most_common.columns = ['Value', 'Count']
                            except TypeError:
                                # Handle unhashable types (like lists) by converting to strings first
                                unique_count = df[field1].astype(str).nunique()
                                non_missing = df[field1].count()
                                most_common = df[field1].astype(str).value_counts().head(10).reset_index()
                                most_common.columns = ['Value', 'Count']
                            
                            stats = f"""
                            <div class='alert alert-info mb-3'>{data_source_note}</div>
                            <div class='alert alert-info'>
                                <p>Field type: Text</p>
                                <p>Unique values: {unique_count}</p>
                                <p>Non-missing values: {non_missing}</p>
                                <p>Missing values: {len(df) - non_missing}</p>
                            </div>
                            <h5>Most Common Values:</h5>
                            {most_common.to_html(classes='table table-striped table-hover', index=False)}
                            """
                
                # 2. Frequency Distribution
                elif analysis_type == 'frequency' and field1:
                    title = f"Frequency Distribution for {field1}"
                    
                    # Check if the field exists in the dataset
                    if field1 not in df.columns:
                        stats = f"<div class='alert alert-warning'>Selected field '{field1}' does not exist in the dataset.</div>"
                    else:
                        field1_type = field_types.get(field1, 'unknown')
                        
                        # Special handling for checkbox fields (containing lists)
                        if field1_type == 'checkbox':
                            # Flatten the lists and count occurrences of each option
                            all_values = []
                            for values in df[field1].dropna():
                                if isinstance(values, list):
                                    all_values.extend(values)
                                elif values:  # Handle non-list values if any
                                    all_values.append(values)
                            
                            if all_values:
                                # Count occurrences of each option
                                value_counts = pd.Series(all_values).value_counts().reset_index()
                                value_counts.columns = ['Value', 'Count']
                                value_counts['Percentage'] = (value_counts['Count'] / len(df) * 100).round(2)
                                
                                # Get missing/empty values count
                                empty_count = df[field1].isna().sum() + df[field1].apply(lambda x: isinstance(x, list) and len(x) == 0).sum()
                                
                                stats = f"""
                                <div class='alert alert-info mb-3'>{data_source_note}</div>
                                <div class='alert alert-info'>
                                    <p>Field type: Checkbox (Multiple Selection)</p>
                                    <p>Total records: {len(df)}</p>
                                    <p>Unique options: {len(value_counts)}</p>
                                    <p>Empty selections: {empty_count} ({(empty_count/len(df)*100).round(2)}%)</p>
                                    <p>Note: Percentages are based on total records, not total selections</p>
                                </div>
                                {value_counts.to_html(classes='table table-striped table-hover', index=False)}
                                """
                                
                                # If we have too many values, only show top N in visualization
                                if len(value_counts) > 15:
                                    plot_data = value_counts.head(15)
                                    has_more = True
                                else:
                                    plot_data = value_counts
                                    has_more = False
                                
                                # Create a bar chart
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.barplot(x='Value', y='Count', data=plot_data, ax=ax)
                                ax.set_title(f'Selected Options in {field1}')
                                if has_more:
                                    ax.set_title(f'Selected Options in {field1} (Top 15 Values)')
                                plt.xticks(rotation=45, ha='right')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Option Distribution',
                                    'img': fig_to_base64(fig)
                                })
                            else:
                                stats = f"<div class='alert alert-warning'>No data available for this checkbox field.</div>"
                        else:
                            # Check if this is an age field for special grouping
                            if is_age_field(field1):
                                # Apply age grouping for frequency distribution
                                df_temp = df.copy()
                                df_temp[f'{field1}_grouped'] = df_temp[field1].apply(categorize_age)
                                
                                # Get value counts for age groups with proper ordering
                                age_groups_series = df_temp[f'{field1}_grouped']
                                age_groups_series = pd.Categorical(age_groups_series, categories=get_age_group_order(), ordered=True)
                                
                                value_counts = age_groups_series.value_counts().reset_index()
                                value_counts.columns = ['Age Group', 'Count']
                                value_counts['Percentage'] = (value_counts['Count'] / value_counts['Count'].sum() * 100).round(2)
                                
                                # Ensure proper ordering by creating categorical with ordered levels
                                value_counts['Age Group'] = pd.Categorical(value_counts['Age Group'], categories=get_age_group_order(), ordered=True)
                                value_counts = value_counts.sort_values('Age Group')
                                
                                # Get missing values count
                                missing_count = df[field1].isna().sum()
                                
                                # Add data source note
                                stats = f"""
                                <div class='alert alert-info mb-3'>{data_source_note}</div>
                                <div class='alert alert-success'>
                                    <p>Age field detected - automatically grouped into meaningful age categories</p>
                                    <p>Original field: {field1}</p>
                                    <p>Total records: {len(df)}</p>
                                    <p>Age groups: {len(value_counts)}</p>
                                    <p>Missing values: {missing_count} ({(missing_count/len(df)*100).round(2)}%)</p>
                                </div>
                                {value_counts.to_html(classes='table table-striped table-hover', index=False)}
                                """
                                
                                plot_data = value_counts
                                
                                # Create a bar chart for age groups
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.barplot(x='Age Group', y='Count', data=plot_data, ax=ax)
                                ax.set_title(f'Age Group Distribution ({field1})')
                                plt.xticks(rotation=45, ha='right')
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Age Group Distribution',
                                    'img': fig_to_base64(fig)
                                })
                            else:
                                # Standard handling for non-checkbox, non-age fields
                                # Get value counts
                                try:
                                    value_counts = df[field1].value_counts().reset_index()
                                    value_counts.columns = ['Value', 'Count']
                                    value_counts['Percentage'] = (value_counts['Count'] / value_counts['Count'].sum() * 100).round(2)
                                except TypeError:
                                    # Handle unhashable types (like lists) by converting to strings first
                                    value_counts = df[field1].astype(str).value_counts().reset_index()
                                    value_counts.columns = ['Value', 'Count']
                                    value_counts['Percentage'] = (value_counts['Count'] / value_counts['Count'].sum() * 100).round(2)
                                
                                # Get missing values count
                                missing_count = df[field1].isna().sum()
                                
                                # Add data source note
                                stats = f"""
                                <div class='alert alert-info mb-3'>{data_source_note}</div>
                                <div class='alert alert-info'>
                                    <p>Total records: {len(df)}</p>
                                    <p>Unique values: {df[field1].astype(str).nunique()}</p>
                                    <p>Missing values: {missing_count} ({(missing_count/len(df)*100).round(2)}%)</p>
                                </div>
                                {value_counts.to_html(classes='table table-striped table-hover', index=False)}
                                """
                                
                                # If we have too many values, only show top N in visualization
                                if len(value_counts) > 15:
                                    plot_data = value_counts.head(15)
                                    has_more = True
                                else:
                                    plot_data = value_counts
                                    has_more = False
                            
                            # Create a bar chart
                            fig, ax = plt.subplots(figsize=(12, 6))
                            sns.barplot(x='Value', y='Count', data=plot_data, ax=ax)
                            ax.set_title(f'Frequency Distribution of {field1}')
                            if has_more:
                                ax.set_title(f'Frequency Distribution of {field1} (Top 15 Values)')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Frequency Distribution',
                                'img': fig_to_base64(fig)
                            })
                
                # 3. Cross-tabulation between two fields
                elif analysis_type == 'crosstab' and field1 and field2:
                    title = f"Cross Tabulation of {field1} and {field2}"
                    
                    # Check if both fields exist in the dataset
                    if field1 not in df.columns or field2 not in df.columns:
                        stats = f"<div class='alert alert-warning'>One or both selected fields do not exist in the dataset.</div>"
                    else:
                        # Check field types and handle appropriately
                        field1_type = field_types.get(field1, 'unknown')
                        field2_type = field_types.get(field2, 'unknown')
                        
                        # Check for special field handling (checkbox or age fields)
                        is_field1_checkbox = field1_type == 'checkbox'
                        is_field2_checkbox = field2_type == 'checkbox'
                        is_field1_age = is_age_field(field1)
                        is_field2_age = is_age_field(field2)
                        
                        # Special handling for checkbox fields or age fields
                        if is_field1_checkbox or is_field2_checkbox or is_field1_age or is_field2_age:
                            try:
                                # Create processed dataframe
                                processed_df = df.copy()
                                processing_notes = []
                                
                                # Function to explode checkbox field into separate rows
                                def explode_checkbox_field(df, field_name):
                                    """Explode a checkbox field (list) into separate rows"""
                                    if field_name not in df.columns:
                                        return df
                                    
                                    # Create a list to store exploded rows
                                    exploded_rows = []
                                    
                                    for idx, row in df.iterrows():
                                        field_value = row[field_name]
                                        
                                        if isinstance(field_value, list) and len(field_value) > 0:
                                            # Create a row for each item in the list
                                            for item in field_value:
                                                new_row = row.copy()
                                                new_row[field_name] = item
                                                exploded_rows.append(new_row)
                                        elif field_value and field_value != [] and pd.notna(field_value):
                                            # Handle non-list values
                                            exploded_rows.append(row)
                                        # Skip empty/null values
                                    
                                    return pd.DataFrame(exploded_rows) if exploded_rows else pd.DataFrame()
                                
                                # Process checkbox fields
                                if is_field1_checkbox:
                                    processed_df = explode_checkbox_field(processed_df, field1)
                                    processing_notes.append(f"Checkbox field '{field1}' has been expanded")
                                if is_field2_checkbox:
                                    processed_df = explode_checkbox_field(processed_df, field2)
                                    processing_notes.append(f"Checkbox field '{field2}' has been expanded")
                                
                                # Process age fields
                                if is_field1_age:
                                    processed_df[f'{field1}_grouped'] = processed_df[field1].apply(categorize_age)
                                    processed_df[field1] = pd.Categorical(processed_df[f'{field1}_grouped'], categories=get_age_group_order(), ordered=True)
                                    processing_notes.append(f"Age field '{field1}' has been grouped into age categories")
                                if is_field2_age:
                                    processed_df[f'{field2}_grouped'] = processed_df[field2].apply(categorize_age)
                                    processed_df[field2] = pd.Categorical(processed_df[f'{field2}_grouped'], categories=get_age_group_order(), ordered=True)
                                    processing_notes.append(f"Age field '{field2}' has been grouped into age categories")
                                
                                if len(processed_df) == 0:
                                    stats = "<div class='alert alert-warning'>No data available for cross-tabulation after processing fields.</div>"
                                else:
                                    # Create cross-tabulation with processed data - preserve categorical ordering
                                    ct = pd.crosstab(processed_df[field1], processed_df[field2], dropna=False)
                                    
                                    # Ensure proper ordering in the resulting crosstab if age fields are involved
                                    if is_field1_age:
                                        # Reorder index (rows) according to age group order
                                        age_order = get_age_group_order()
                                        existing_indices = [idx for idx in age_order if idx in ct.index]
                                        ct = ct.reindex(existing_indices)
                                    
                                    if is_field2_age:
                                        # Reorder columns according to age group order
                                        age_order = get_age_group_order()
                                        existing_columns = [col for col in age_order if col in ct.columns]
                                        ct = ct.reindex(columns=existing_columns)
                                    
                                    # Create notes about processing
                                    notes_html = "<div class='alert alert-info'><strong>Field Processing Notes:</strong><ul>"
                                    for note in processing_notes:
                                        notes_html += f"<li>{note}</li>"
                                    notes_html += "</ul></div>"
                                    
                                    stats = notes_html + ct.to_html(classes='table table-striped table-hover')
                                    
                                    # Show row and column totals
                                    ct_with_totals = pd.crosstab(processed_df[field1], processed_df[field2], margins=True, margins_name="Total", dropna=False)
                                    
                                    # Apply same ordering to totals table if age fields are involved
                                    if is_field1_age:
                                        age_order = get_age_group_order()
                                        existing_indices = [idx for idx in age_order if idx in ct_with_totals.index and idx != "Total"] + ["Total"]
                                        ct_with_totals = ct_with_totals.reindex(existing_indices)
                                    
                                    if is_field2_age:
                                        age_order = get_age_group_order()
                                        existing_columns = [col for col in age_order if col in ct_with_totals.columns and col != "Total"] + ["Total"]
                                        ct_with_totals = ct_with_totals.reindex(columns=existing_columns)
                                    
                                    stats += "<h5>With Row/Column Totals:</h5>"
                                    stats += ct_with_totals.to_html(classes='table table-striped table-hover')
                                    
                                    # Create visualizations
                                    if len(ct) > 0 and len(ct.columns) > 0:
                                        # Heatmap
                                        fig, ax = plt.subplots(figsize=(12, 8))
                                        sns.heatmap(ct, annot=True, fmt='d', cmap='YlGnBu', ax=ax)
                                        ax.set_title(f'Heatmap - {title}')
                                        ax.set_xlabel(field2)
                                        ax.set_ylabel(field1)
                                        plt.tight_layout()
                                        plots.append({
                                            'title': 'Heatmap - Cross-tabulation (Processed Data)',
                                            'img': fig_to_base64(fig)
                                        })
                                        
                                        # Stacked bar chart
                                        fig, ax = plt.subplots(figsize=(12, 8))
                                        ct_pct = ct.div(ct.sum(axis=1), axis=0)
                                        ct_pct.plot(kind='bar', stacked=True, ax=ax)
                                        ax.set_title(f'Stacked Bar Chart - {title}')
                                        ax.set_xlabel(field1)
                                        ax.set_ylabel('Proportion')
                                        ax.legend(title=field2, bbox_to_anchor=(1.05, 1), loc='upper left')
                                        plt.tight_layout()
                                        plots.append({
                                            'title': 'Stacked Bar Chart (Processed Data)',
                                            'img': fig_to_base64(fig)
                                        })
                                        
                                        # Show percentages
                                        ct_pct = ct.div(ct.sum(axis=1), axis=0) * 100
                                        ct_pct = ct_pct.round(2).astype(str) + '%'
                                        
                                        # Apply same ordering to percentage table if age fields are involved
                                        if is_field1_age:
                                            age_order = get_age_group_order()
                                            existing_indices = [idx for idx in age_order if idx in ct_pct.index]
                                            ct_pct = ct_pct.reindex(existing_indices)
                                        
                                        if is_field2_age:
                                            age_order = get_age_group_order()
                                            existing_columns = [col for col in age_order if col in ct_pct.columns]
                                            ct_pct = ct_pct.reindex(columns=existing_columns)
                                        
                                        stats += "<h5>Percentages (Row-wise):</h5>"
                                        stats += ct_pct.to_html(classes='table table-striped table-hover')
                                        
                            except Exception as e:
                                stats = f"<div class='alert alert-danger'>Error processing fields for cross-tabulation: {str(e)}</div>"
                        # Cross-tab for categorical vs categorical
                        elif field1_type == 'categorical' and field2_type == 'categorical':
                            try:
                                # Create cross-tabulation
                                ct = pd.crosstab(df[field1], df[field2])
                                stats = ct.to_html(classes='table table-striped table-hover')
                                
                                # Heatmap
                                fig, ax = plt.subplots(figsize=(12, 8))
                                sns.heatmap(ct, annot=True, fmt='d', cmap='YlGnBu', ax=ax)
                                ax.set_title(f'Heatmap - {title}')
                                ax.set_xlabel(field2)
                                ax.set_ylabel(field1)
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
                                ax.set_xlabel(field1)
                                ax.set_ylabel('Proportion')
                                ax.legend(title=field2)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Stacked Bar Chart',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Also show percentages
                                ct_pct = ct.div(ct.sum(axis=1), axis=0) * 100
                                ct_pct = ct_pct.round(2).astype(str) + '%'
                                stats += "<h5>Percentages (Row-wise):</h5>"
                                stats += ct_pct.to_html(classes='table table-striped table-hover')
                            except TypeError:
                                # Handle unhashable types (like lists)
                                stats = "<div class='alert alert-warning'>Cannot create cross-tabulation because one or both fields contain unhashable values (like lists or objects). Try using string conversion or a different analysis.</div>"
                                
                                # Try creating the cross-tab with string conversion
                                try:
                                    ct = pd.crosstab(df[field1].astype(str), df[field2].astype(str))
                                    stats += "<h5>Cross-tabulation with string conversion:</h5>"
                                    stats += ct.to_html(classes='table table-striped table-hover')
                                except:
                                    # If even that fails, just leave the error message
                                    pass
                        # Numeric vs categorical
                        elif field1_type == 'numeric' and field2_type == 'categorical':
                            # Group numeric data by categories
                            grouped = df.groupby(field2)[field1].agg(['mean', 'median', 'std', 'count']).round(2)
                            stats = grouped.to_html(classes='table table-striped table-hover')
                            
                            # Create a box plot
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.boxplot(x=field2, y=field1, data=df, ax=ax)
                            ax.set_title(f'Boxplot - {title}')
                            ax.set_xlabel(field2)
                            ax.set_ylabel(field1)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Boxplot',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Bar chart of means
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.barplot(x=field2, y=field1, data=df, estimator=np.mean, ci=None, ax=ax)
                            ax.set_title(f'Mean {field1} by {field2}')
                            ax.set_xlabel(field2)
                            ax.set_ylabel(f'Mean {field1}')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Mean Bar Chart',
                                'img': fig_to_base64(fig)
                            })
                        
                        # Categorical vs numeric (swap axes)
                        elif field1_type == 'categorical' and field2_type == 'numeric':
                            # Group numeric data by categories
                            grouped = df.groupby(field1)[field2].agg(['mean', 'median', 'std', 'count']).round(2)
                            stats = grouped.to_html(classes='table table-striped table-hover')
                            
                            # Create a box plot
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.boxplot(x=field1, y=field2, data=df, ax=ax)
                            ax.set_title(f'Boxplot - {title}')
                            ax.set_xlabel(field1)
                            ax.set_ylabel(field2)
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Boxplot',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Bar chart of means
                            fig, ax = plt.subplots(figsize=(12, 8))
                            sns.barplot(x=field1, y=field2, data=df, estimator=np.mean, ci=None, ax=ax)
                            ax.set_title(f'Mean {field2} by {field1}')
                            ax.set_xlabel(field1)
                            ax.set_ylabel(f'Mean {field2}')
                            plt.xticks(rotation=45, ha='right')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Mean Bar Chart',
                                'img': fig_to_base64(fig)
                            })
                        
                        # Numeric vs numeric
                        elif field1_type == 'numeric' and field2_type == 'numeric':
                            # Calculate correlation
                            correlation = df[[field1, field2]].corr().iloc[0, 1].round(3)
                            
                            stats = f"""
                            <div class='alert alert-info'>
                                <p>Correlation coefficient: {correlation}</p>
                                <p>Number of observations: {df[[field1, field2]].dropna().shape[0]}</p>
                            </div>
                            """
                            
                            # Create a scatter plot
                            fig, ax = plt.subplots(figsize=(10, 8))
                            sns.scatterplot(x=field1, y=field2, data=df, ax=ax)
                            ax.set_title(f'Scatter Plot of {field1} vs {field2} (r = {correlation})')
                            ax.set_xlabel(field1)
                            ax.set_ylabel(field2)
                            # Add regression line
                            sns.regplot(x=field1, y=field2, data=df, scatter=False, ax=ax, color='red')
                            plt.tight_layout()
                            plots.append({
                                'title': 'Scatter Plot',
                                'img': fig_to_base64(fig)
                            })
                            
                            # Create a hex bin plot for large datasets
                            if len(df) > 500:
                                fig, ax = plt.subplots(figsize=(10, 8))
                                plt.hexbin(df[field1], df[field2], gridsize=20, cmap='Blues')
                                plt.colorbar(label='Count')
                                ax.set_title(f'Hexbin Plot of {field1} vs {field2} (r = {correlation})')
                                ax.set_xlabel(field1)
                                ax.set_ylabel(field2)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Hexbin Plot (Better for Large Datasets)',
                                    'img': fig_to_base64(fig)
                                })
                        else:
                            stats = "<div class='alert alert-warning'>Fields must be either categorical or numeric for cross-tabulation.</div>"
                
                # 4. Time Series
                elif analysis_type == 'timeseries' and field1:
                    title = f"Time Series Analysis for {field1}"
                    
                    # Check if the field exists in the dataset
                    if field1 not in df.columns:
                        stats = f"<div class='alert alert-warning'>Selected field '{field1}' does not exist in the dataset.</div>"
                    else:
                        # Check if we have timestamp data from created_at column
                        has_time_data = False
                        if 'created_at' in df.columns:
                            # Convert to datetime
                            df['date'] = pd.to_datetime(df['created_at']).dt.date
                            has_time_data = True
                        # If no created_at, try to extract date from patient_id (format: DDMMYY-NNNN)
                        elif 'patient_id' in df.columns:
                            try:
                                # Extract DDMMYY part from patient_id and convert to datetime
                                df['extracted_date'] = df['patient_id'].str.extract(r'(\d{6})-', expand=False)
                                # Convert to datetime format (add 20 or 19 as prefix for year based on current date)
                                current_year = datetime.now(EAT).year
                                
                                def convert_to_date(date_str):
                                    if pd.isna(date_str):
                                        return None
                                    try:
                                        day = int(date_str[0:2])
                                        month = int(date_str[2:4])
                                        year_short = int(date_str[4:6])
                                        # Determine century (19xx or 20xx)
                                        year = year_short + 2000 if year_short <= (current_year - 2000) else year_short + 1900
                                        return datetime(year, month, day).date()
                                    except:
                                        return None
                                
                                df['date'] = df['extracted_date'].apply(convert_to_date)
                                # Drop rows with invalid dates
                                df = df.dropna(subset=['date'])
                                if len(df) > 0:
                                    has_time_data = True
                                    print(f"Successfully extracted dates from {len(df)} patient IDs")
                            except Exception as e:
                                print(f"Error extracting dates from patient_id: {str(e)}")
                                has_time_data = False
                            
                        # Proceed if we have date data
                        if has_time_data:
                            # Analyze based on field type
                            field1_type = field_types.get(field1, 'unknown')
                            
                            if field1_type == 'numeric':
                                # Group by date and calculate statistics
                                time_data = df.groupby('date')[field1].agg(['mean', 'count', 'std', 'min', 'max']).reset_index()
                                
                                # Add data source note
                                stats = f"<div class='alert alert-info mb-3'>{data_source_note}</div>"
                                stats += time_data.to_html(classes='table table-striped table-hover', index=False)
                                
                                # Create line chart for mean values over time
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.lineplot(x='date', y='mean', data=time_data, marker='o', ax=ax)
                                ax.set_title(f'Average {field1} Over Time')
                                ax.set_xlabel('Date')
                                ax.set_ylabel(f'Average {field1}')
                                plt.xticks(rotation=45)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Time Series - Average Values',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Create line chart for count of records over time
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.lineplot(x='date', y='count', data=time_data, marker='o', ax=ax)
                                ax.set_title(f'Number of Records Over Time')
                                ax.set_xlabel('Date')
                                ax.set_ylabel('Number of Records')
                                plt.xticks(rotation=45)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Time Series - Record Counts',
                                    'img': fig_to_base64(fig)
                                })
                                
                            elif field1_type == 'categorical':
                                # Create pivot table to show counts of each category over time
                                pivot_data = df.pivot_table(
                                    index='date',
                                    columns=field1,
                                    values='patient_id',
                                    aggfunc='count',
                                    fill_value=0
                                ).reset_index()
                                
                                # Melt the pivot table for easier plotting
                                melt_data = pd.melt(
                                    pivot_data, 
                                    id_vars=['date'], 
                                    value_vars=[col for col in pivot_data.columns if col != 'date'],
                                    var_name=field1,
                                    value_name='count'
                                )
                                
                                # Create line chart for each category
                                fig, ax = plt.subplots(figsize=(12, 6))
                                sns.lineplot(x='date', y='count', hue=field1, data=melt_data, marker='o', ax=ax)
                                ax.set_title(f'Count of {field1} Categories Over Time')
                                ax.set_xlabel('Date')
                                ax.set_ylabel('Count')
                                plt.xticks(rotation=45)
                                plt.legend(title=field1)
                                plt.tight_layout()
                                plots.append({
                                    'title': 'Time Series by Category',
                                    'img': fig_to_base64(fig)
                                })
                                
                                # Output the stacked data in a table
                                stats = f"<div class='alert alert-info mb-3'>{data_source_note}</div>"
                                stats += pivot_data.reset_index().to_html(classes='table table-striped table-hover')
                        
                        else:
                            stats = "<div class='alert alert-warning'>No time data available for time series analysis. Please ensure patient IDs follow the DDMMYY-NNNN format or submissions have creation dates.</div>"

                # 5. Correlation Matrix
                elif analysis_type == 'correlation':
                    title = 'Correlation Matrix Analysis'
                    
                    # Use selected fields if provided, otherwise use all numeric fields
                    if correlation_fields and len(correlation_fields) >= 2:
                        selected_numeric_fields = correlation_fields
                        title = f'Correlation Matrix Analysis for Selected Fields ({len(selected_numeric_fields)} fields)'
                    else:
                        # Find all numeric fields
                        selected_numeric_fields = [field for field, type_val in field_types.items() if type_val == 'numeric']
                        title = f'Correlation Matrix Analysis for All Numeric Fields ({len(selected_numeric_fields)} fields)'
                    
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
                        
                        plt.title('Correlation Matrix')
                        plt.tight_layout()
                        plots.append({
                            'title': 'Correlation Matrix Heatmap',
                            'img': fig_to_base64(fig)
                        })
                        
                        # Create a table for the full correlation matrix
                        stats = corr_matrix.to_html(classes='table table-striped table-hover')
                        
                        # Add interpretation for strongest correlations
                        strong_correlations = []
                        
                        # Extract upper triangle of correlation matrix (excluding diagonal)
                        for i in range(len(corr_matrix.columns)):
                            for j in range(i+1, len(corr_matrix.columns)):
                                col1 = corr_matrix.columns[i]
                                col2 = corr_matrix.columns[j]
                                corr_val = corr_matrix.iloc[i, j]
                                
                                # Only include strong correlations (positive or negative)
                                if abs(corr_val) >= 0.5:
                                    strong_correlations.append({
                                        'field1': col1,
                                        'field2': col2,
                                        'correlation': corr_val,
                                        'abs_corr': abs(corr_val)
                                    })
                        
                        # Sort by absolute correlation strength (descending)
                        strong_correlations = sorted(strong_correlations, key=lambda x: x['abs_corr'], reverse=True)
                        
                        if strong_correlations:
                            strong_corr_df = pd.DataFrame(strong_correlations)
                            strong_corr_df = strong_corr_df[['field1', 'field2', 'correlation']]
                            
                            stats += "<h5>Strongest Correlations:</h5>"
                            stats += strong_corr_df.to_html(classes='table table-striped table-hover', index=False)
    
    # Get all camps for filter dropdown
    camps_data = fetch_all_pages(
        supabase.table('camps').select('*').order('start_date', desc=True),
        debug_name="camps_for_analytics_filter"
    )
    
    # Render the template with all data
    return render_template('analytics.html',
                          title=title if title else 'Analytics',
                          all_projects=all_projects,
                          forms=forms,
                          camps=camps_data,
                          selected_project=project_id,
                          selected_form=form_id,
                          selected_camp=camp_id,
                          selected_camp_name=selected_camp['name'] if selected_camp else None,
                          start_date=start_date,
                          end_date=end_date,
                          fields=all_fields,
                          selected_analysis=analysis_type,
                          selected_field1=field1,
                          selected_field2=field2,
                          field_types=field_types,
                          plots=plots,
                          stats=stats,
                          correlation_fields=correlation_fields)

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
    camp_id = request.args.get('camp_id')
    analysis_type = request.args.get('analysis_type')
    field1 = request.args.get('field1')
    field2 = request.args.get('field2')
    export_format = request.args.get('format', 'excel')  # Default to excel
    
    # Handle camp filtering - if camp_id is provided, override start_date and end_date
    selected_camp = None
    if camp_id:
        try:
            camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
            if camp_response.data:
                selected_camp = camp_response.data[0]
                start_date = selected_camp['start_date']
                end_date = selected_camp['end_date']
                print(f"Export Analytics: Using camp '{selected_camp['name']}' dates: {start_date} to {end_date}")
        except Exception as e:
            print(f"Export Analytics: Error fetching camp details: {str(e)}")
            # If camp lookup fails, continue with original dates
    
    # Get correlation fields (multiple selection)
    correlation_fields = request.args.getlist('correlation_fields[]')
    
    # Log export action
    log_details = f"Export Analytics - Project: {project_id or 'All'}, Form: {form_id or 'All'}, Analysis: {analysis_type}"
    if camp_id and selected_camp:
        log_details += f", Camp: {selected_camp['name']}"
    elif start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    log_activity('generate', 'analytics_export', None, log_details)
    
    # Require project_id
    if not project_id:
        flash('Project ID is required for analytics export.', 'danger')
        return redirect(url_for('analytics'))
    
    # Prepare dataset using the enhanced function that directly mirrors the dataset view
    df = prepare_dataset_for_analysis(project_id, form_id, start_date, end_date)
    
    if df.empty:
        flash('No data available for the selected program.', 'warning')
        return redirect(url_for('analytics', project_id=project_id))
    
    # Generate filename
    filename = 'analytics'
    if project_id:
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            project_name = project_response.data[0]['name']
            filename = f"{project_name}_analytics"
    
    # Only add form name to filename when filtering by specific form (no project_id)
    if form_id and not project_id:
        form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
        if form_response.data:
            form_title = form_response.data[0]['title']
            filename = f"{filename}_{form_title}"
    
    if analysis_type:
        filename = f"{filename}_{analysis_type}"
    
    # Generate field_types for checkbox detection
    field_types = {}
    all_fields = [col for col in df.columns if col not in ['patient_id', 'full_name', 'created_at', 'updated_at']]
    
    # Determine field types for analysis
    for field in all_fields:
        # First check if this field contains lists (checkbox data)
        contains_lists = False
        try:
            # Check if any value in this field is a list
            contains_lists = df[field].apply(lambda x: isinstance(x, list)).any()
            if contains_lists:
                field_types[field] = 'checkbox'
                continue
        except:
            # If we can't check (e.g., field is empty), assume it's not a list
            pass
        
        if df[field].dtype == 'object':  # String/categorical
            # Try to convert to numeric, setting errors='coerce' will convert failures to NaN
            numeric_series = pd.to_numeric(df[field], errors='coerce')
            # If the conversion didn't result in all NaNs, consider it numeric
            if not numeric_series.isna().all():
                field_types[field] = 'numeric'
            else:
                field_types[field] = 'categorical'
        elif pd.api.types.is_numeric_dtype(df[field]):
            field_types[field] = 'numeric'
        elif pd.api.types.is_datetime64_any_dtype(df[field]):
            field_types[field] = 'datetime'
        else:
            field_types[field] = 'unknown'
    
    # For CSV format
    if export_format == 'csv':
        output = StringIO()
        
        # The dataset is already filtered to include only patients who participated in the selected program
        df.to_csv(output, index=False)
        
        # If we have a specific analysis type, include the specific analysis as well
        if analysis_type == 'correlation' and correlation_fields:
            if len(correlation_fields) >= 2:
                # Convert fields to numeric before correlation
                numeric_df = df[correlation_fields].apply(pd.to_numeric, errors='coerce')
                corr_matrix = numeric_df.corr().round(3)
                corr_matrix.to_csv(output)
        elif analysis_type == 'crosstab' and field1 and field2:
            # Export crosstab
            if field1 in df.columns and field2 in df.columns:
                try:
                    # Check field types for checkbox handling
                    field1_type = field_types.get(field1, 'unknown')
                    field2_type = field_types.get(field2, 'unknown')
                    
                    # Handle checkbox fields or age fields
                    is_field1_age = is_age_field(field1)
                    is_field2_age = is_age_field(field2)
                    
                    if field1_type == 'checkbox' or field2_type == 'checkbox' or is_field1_age or is_field2_age:
                        # Function to explode checkbox field into separate rows (same as in analytics)
                        def explode_checkbox_field_export(df, field_name):
                            """Explode a checkbox field (list) into separate rows for export"""
                            if field_name not in df.columns:
                                return df
                            
                            exploded_rows = []
                            for idx, row in df.iterrows():
                                field_value = row[field_name]
                                
                                if isinstance(field_value, list) and len(field_value) > 0:
                                    for item in field_value:
                                        new_row = row.copy()
                                        new_row[field_name] = item
                                        exploded_rows.append(new_row)
                                elif field_value and field_value != [] and pd.notna(field_value):
                                    exploded_rows.append(row)
                            
                            return pd.DataFrame(exploded_rows) if exploded_rows else pd.DataFrame()
                        
                        # Create processed dataframe
                        processed_df = df.copy()
                        processing_notes = []
                        
                        # Process checkbox fields
                        if field1_type == 'checkbox':
                            processed_df = explode_checkbox_field_export(processed_df, field1)
                            processing_notes.append(f"Checkbox field '{field1}' has been expanded")
                        if field2_type == 'checkbox':
                            processed_df = explode_checkbox_field_export(processed_df, field2)
                            processing_notes.append(f"Checkbox field '{field2}' has been expanded")
                        
                        # Process age fields
                        if is_field1_age:
                            processed_df[f'{field1}_grouped'] = processed_df[field1].apply(categorize_age)
                            processed_df[field1] = pd.Categorical(processed_df[f'{field1}_grouped'], categories=get_age_group_order(), ordered=True)
                            processing_notes.append(f"Age field '{field1}' has been grouped into age categories")
                        if is_field2_age:
                            processed_df[f'{field2}_grouped'] = processed_df[field2].apply(categorize_age)
                            processed_df[field2] = pd.Categorical(processed_df[f'{field2}_grouped'], categories=get_age_group_order(), ordered=True)
                            processing_notes.append(f"Age field '{field2}' has been grouped into age categories")
                        
                        if len(processed_df) > 0:
                            # Write processing notes
                            for note in processing_notes:
                                output.write(f"Note: {note}\n")
                            output.write("\n")
                            
                            ct = pd.crosstab(processed_df[field1], processed_df[field2], dropna=False)
                            
                            # Ensure proper ordering in the resulting crosstab if age fields are involved
                            if is_field1_age:
                                age_order = get_age_group_order()
                                existing_indices = [idx for idx in age_order if idx in ct.index]
                                ct = ct.reindex(existing_indices)
                            
                            if is_field2_age:
                                age_order = get_age_group_order()
                                existing_columns = [col for col in age_order if col in ct.columns]
                                ct = ct.reindex(columns=existing_columns)
                            
                            ct.to_csv(output)
                        else:
                            output.write("No data available for cross-tabulation after processing fields.\n")
                    else:
                        # Regular crosstab for non-checkbox fields
                        ct = pd.crosstab(df[field1], df[field2])
                        ct.to_csv(output)
                except TypeError:
                    # Handle unhashable types like lists (fallback)
                    try:
                        ct = pd.crosstab(df[field1].astype(str), df[field2].astype(str))
                        output.write("Note: Values were converted to strings for cross-tabulation due to unhashable types\n\n")
                        ct.to_csv(output)
                    except Exception as e:
                        output.write(f"Error creating cross-tabulation: {str(e)}\n")
                        df[[field1, field2]].to_csv(output, index=False)
        elif analysis_type == 'timeseries' and field1:
            # Export time series data
            if 'created_at' in df.columns and field1 in df.columns:
                df['date'] = pd.to_datetime(df['created_at']).dt.date
                time_data = df.groupby('date')[field1].agg(['mean', 'count', 'std', 'min', 'max']).reset_index()
                time_data.to_csv(output, index=False)
        
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
            # Write the main dataset - already filtered to include only patients who participated in the selected program
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
                # Use selected fields if provided, otherwise use all numeric fields
                if correlation_fields and len(correlation_fields) >= 2:
                    selected_numeric_fields = correlation_fields
                else:
                    # Find all numeric fields
                    selected_numeric_fields = []
                    for column in df.columns:
                        if np.issubdtype(df[column].dtype, np.number):
                            selected_numeric_fields.append(column)
                
                if len(selected_numeric_fields) >= 2:
                    # Convert fields to numeric before correlation
                    numeric_df = df[selected_numeric_fields].apply(pd.to_numeric, errors='coerce')
                    corr_matrix = numeric_df.corr().round(3)
                    
                    corr_matrix.to_excel(writer, sheet_name='Correlation Matrix')
                    
                    # Apply header formatting
                    worksheet = writer.sheets['Correlation Matrix']
                    for col_num, value in enumerate([''] + list(corr_matrix.columns)):
                        worksheet.write(0, col_num, value, header_format)
                    
            elif analysis_type == 'crosstab' and field1 and field2:
                if field1 in df.columns and field2 in df.columns:
                    try:
                        # Check field types for checkbox handling
                        field1_type = field_types.get(field1, 'unknown')
                        field2_type = field_types.get(field2, 'unknown')
                        
                        # Handle checkbox fields or age fields
                        is_field1_age = is_age_field(field1)
                        is_field2_age = is_age_field(field2)
                        
                        if field1_type == 'checkbox' or field2_type == 'checkbox' or is_field1_age or is_field2_age:
                            # Function to explode checkbox field into separate rows (same as in analytics)
                            def explode_checkbox_field_excel(df, field_name):
                                """Explode a checkbox field (list) into separate rows for Excel export"""
                                if field_name not in df.columns:
                                    return df
                                
                                exploded_rows = []
                                for idx, row in df.iterrows():
                                    field_value = row[field_name]
                                    
                                    if isinstance(field_value, list) and len(field_value) > 0:
                                        for item in field_value:
                                            new_row = row.copy()
                                            new_row[field_name] = item
                                            exploded_rows.append(new_row)
                                    elif field_value and field_value != [] and pd.notna(field_value):
                                        exploded_rows.append(row)
                                
                                return pd.DataFrame(exploded_rows) if exploded_rows else pd.DataFrame()
                            
                            # Create processed dataframe
                            processed_df = df.copy()
                            processing_notes = []
                            
                            # Process checkbox fields
                            if field1_type == 'checkbox':
                                processed_df = explode_checkbox_field_excel(processed_df, field1)
                                processing_notes.append(f"Checkbox field '{field1}' has been expanded")
                            if field2_type == 'checkbox':
                                processed_df = explode_checkbox_field_excel(processed_df, field2)
                                processing_notes.append(f"Checkbox field '{field2}' has been expanded")
                            
                            # Process age fields
                            if is_field1_age:
                                processed_df[f'{field1}_grouped'] = processed_df[field1].apply(categorize_age)
                                processed_df[field1] = pd.Categorical(processed_df[f'{field1}_grouped'], categories=get_age_group_order(), ordered=True)
                                processing_notes.append(f"Age field '{field1}' has been grouped into age categories")
                            if is_field2_age:
                                processed_df[f'{field2}_grouped'] = processed_df[field2].apply(categorize_age)
                                processed_df[field2] = pd.Categorical(processed_df[f'{field2}_grouped'], categories=get_age_group_order(), ordered=True)
                                processing_notes.append(f"Age field '{field2}' has been grouped into age categories")
                            
                            if len(processed_df) > 0:
                                # Add notes about field processing
                                notes_text = "Field Processing Notes: " + "; ".join(processing_notes)
                                notes_df = pd.DataFrame([[notes_text]], columns=["Cross Tabulation"])
                                notes_df.to_excel(writer, sheet_name='Cross Tabulation', index=False)
                                
                                ct = pd.crosstab(processed_df[field1], processed_df[field2], dropna=False)
                                
                                # Ensure proper ordering in the resulting crosstab if age fields are involved
                                if is_field1_age:
                                    age_order = get_age_group_order()
                                    existing_indices = [idx for idx in age_order if idx in ct.index]
                                    ct = ct.reindex(existing_indices)
                                
                                if is_field2_age:
                                    age_order = get_age_group_order()
                                    existing_columns = [col for col in age_order if col in ct.columns]
                                    ct = ct.reindex(columns=existing_columns)
                                
                                ct.to_excel(writer, sheet_name='Cross Tabulation', startrow=3)
                                
                                # Apply header formatting
                                worksheet = writer.sheets['Cross Tabulation']
                                for col_num, value in enumerate([''] + list(ct.columns)):
                                    worksheet.write(3, col_num, value, header_format)
                            else:
                                # No data available after processing
                                notes_df = pd.DataFrame([["No data available for cross-tabulation after processing fields."]], 
                                                      columns=["Cross Tabulation"])
                                notes_df.to_excel(writer, sheet_name='Cross Tabulation', index=False)
                        else:
                            # Regular crosstab for non-checkbox fields
                            ct = pd.crosstab(df[field1], df[field2])
                            ct.to_excel(writer, sheet_name='Cross Tabulation')
                        
                        # Apply header formatting
                        worksheet = writer.sheets['Cross Tabulation']
                        for col_num, value in enumerate([''] + list(ct.columns)):
                            worksheet.write(0, col_num, value, header_format)
                    except TypeError:
                        # Handle unhashable types like lists (fallback)
                        try:
                            # Convert to strings
                            ct = pd.crosstab(df[field1].astype(str), df[field2].astype(str))
                            
                            # Add a note about the conversion
                            notes_df = pd.DataFrame([["Note: Values were converted to strings for cross-tabulation due to unhashable types (like lists)"]], 
                                                  columns=["Cross Tabulation"])
                            notes_df.to_excel(writer, sheet_name='Cross Tabulation', index=False)
                            
                            # Write the crosstab starting a few rows down
                            ct.to_excel(writer, sheet_name='Cross Tabulation', startrow=3)
                            
                            # Apply header formatting
                            worksheet = writer.sheets['Cross Tabulation']
                            for col_num, value in enumerate([''] + list(ct.columns)):
                                worksheet.write(3, col_num, value, header_format)
                        except Exception as e:
                            # If all else fails, just output the raw data columns
                            notes_df = pd.DataFrame([["Error creating cross-tabulation due to unhashable types. Raw data shown below."]], 
                                                  columns=["Cross Tabulation Error"])
                            notes_df.to_excel(writer, sheet_name='Cross Tabulation', index=False)
                            df[[field1, field2]].to_excel(writer, sheet_name='Cross Tabulation', startrow=3)
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
        
        # Check if we have the new structured fields_data
        fields_data_json = request.form.get('fields_data')
        if fields_data_json:
            print(f"🆕 EDIT: Using NEW field-centric approach")
            try:
                fields = json.loads(fields_data_json)
                print(f"✅ EDIT: Received {len(fields)} structured fields:")
                for i, field in enumerate(fields):
                    print(f"  Field {i}: {field['label']} - Condition: {field.get('condition', 'None')}")
                print(f"🎯 EDIT: Skipping old array processing, using field-centric data directly")
                    
            except json.JSONDecodeError as e:
                print(f"❌ EDIT: JSON decode error: {e}")
                flash('Invalid fields data format.', 'danger')
                return redirect(url_for('view_form', form_id=form_id))
        else:
            print(f"🔄 EDIT: Using OLD array approach (fallback)")
            # Fall back to old approach for compatibility
            labels = request.form.getlist('field_labels[]')
            types = request.form.getlist('field_types[]')
            options_list = request.form.getlist('field_options[]')
            location_identifiers = request.form.getlist('location_field_identifier[]')
            required_fields = request.form.getlist('field_required[]')
            allow_other_fields = request.form.getlist('allow_other[]')
        
            # Conditional field data
            is_conditional_fields = request.form.getlist('is_conditional[]')
            condition_fields = request.form.getlist('condition_field[]')
            condition_operators = request.form.getlist('condition_operator[]')
            condition_values = request.form.getlist('condition_value[]')
            condition_logic = request.form.getlist('condition_logic[]')
            
            # Debug conditional fields data for EDIT
            print(f"🔍 EDIT FORM SUBMISSION DEBUG:")
            print(f"DEBUG EDIT - Total fields: {len(labels)}")
            print(f"DEBUG EDIT - Labels: {labels}")
            print(f"DEBUG EDIT - is_conditional_fields: {is_conditional_fields}")
            print(f"DEBUG EDIT - condition_fields: {condition_fields}")
            print(f"DEBUG EDIT - condition_operators: {condition_operators}")
            print(f"DEBUG EDIT - condition_values: {condition_values}")
            print(f"DEBUG EDIT - condition_logic: {condition_logic}")
            
            # Debug: show exactly which fields should have conditions
            for i, conditional_field_idx in enumerate(is_conditional_fields):
                if conditional_field_idx and int(conditional_field_idx) < len(labels):
                    field_name = labels[int(conditional_field_idx)]
                    print(f"🎯 EDIT Conditional field #{conditional_field_idx}: '{field_name}'")
                    if i < len(condition_fields):
                        print(f"   ➜ Should depend on: '{condition_fields[i]}'")
                    if i < len(condition_operators):
                        print(f"   ➜ Operator: '{condition_operators[i]}'")
                    if i < len(condition_values):
                        print(f"   ➜ Value: '{condition_values[i]}'")
                    if i < len(condition_logic):
                        print(f"   ➜ Logic: '{condition_logic[i]}'")
                    print()
            
            # Validate old array data
            if not labels:
                flash('At least one field is required.', 'danger')
                return redirect(url_for('project_detail', project_id=project_id))
            
            # Process old array data into fields
            fields = []
            location_idx = 0
            for i in range(len(labels)):
                field = {
                    'label': labels[i].strip(),
                    'type': types[i],
                    'options': [opt.strip() for opt in options_list[i].split(',') if opt.strip()] if types[i] in ['dropdown', 'radio', 'checkbox'] else [],
                    'required': str(i) in required_fields
                }
                if types[i] in ['radio', 'checkbox']:
                    field['allow_other'] = str(i) in allow_other_fields
                if labels[i] in ['Region', 'District', 'Ward'] and location_idx < len(location_identifiers):
                    field['location_field_identifier'] = location_identifiers[location_idx]
                    field['type'] = 'dropdown'
                    field['options'] = []
                    location_idx += 1
                else:
                    field['location_field_identifier'] = None
                
                # Add conditional logic if this field is conditional
                is_in_conditional = str(i) in is_conditional_fields
                
                print(f"DEBUG EDIT - Field {i} ({labels[i]}):")
                print(f"  - str(i) = '{str(i)}'")
                print(f"  - is_conditional_fields = {is_conditional_fields}")
                print(f"  - is '{str(i)}' in conditional list? {is_in_conditional}")
                
                if is_in_conditional:
                    # Collect ALL conditions for this field (multiple conditions support)
                    field_conditions = []
                    field_logic = 'OR'  # Default logic
                    
                    print(f"  - Collecting all conditions for field {i}")
                    
                    # Strategy: collect conditions starting from conditional field position
                    
                    # Find the position of this field in the conditional fields list
                    try:
                        current_field_position = is_conditional_fields.index(str(i))
                        print(f"  - Field {i} is at conditional position {current_field_position}")
                        
                        # Find where the next conditional field's conditions start
                        next_condition_start = len(condition_fields)  # Default to end of array
                        if current_field_position + 1 < len(is_conditional_fields):
                            next_field_idx = int(is_conditional_fields[current_field_position + 1])
                            next_field_position = is_conditional_fields.index(str(next_field_idx))
                            next_condition_start = next_field_position
                            print(f"  - Next conditional field {next_field_idx} starts at condition position {next_condition_start}")
                        
                        # Collect ALL conditions for this field starting from its position
                        condition_start_idx = current_field_position
                        condition_end_idx = next_condition_start
                        
                        print(f"  - Collecting conditions from index {condition_start_idx} to {condition_end_idx-1}")
                        
                        for condition_idx in range(condition_start_idx, min(condition_end_idx, len(condition_fields))):
                            if (condition_idx < len(condition_fields) and 
                                condition_idx < len(condition_operators) and 
                                condition_idx < len(condition_values)):
                                
                                dependent_field = condition_fields[condition_idx].strip()
                                operator = condition_operators[condition_idx] if condition_idx < len(condition_operators) else 'equals'
                                value = condition_values[condition_idx] if condition_idx < len(condition_values) else ''
                                
                                # Only add condition if dependent field is not empty
                                if dependent_field:
                                    condition_rule = {
                                        'dependent_field': dependent_field,
                                        'operator': operator,
                                        'value': value
                                    }
                                    field_conditions.append(condition_rule)
                                    print(f"  - Added condition {len(field_conditions)}: {condition_rule}")
                                    
                                    # Get logic for this field (use the first logic we encounter)
                                    if len(field_conditions) == 1 and condition_idx < len(condition_logic):
                                        field_logic = condition_logic[condition_idx]
                                        print(f"  - Using logic: {field_logic}")
                                else:
                                    print(f"  - Skipping empty condition at index {condition_idx}")
                        
                        # Create the final condition structure
                        if field_conditions:
                            if len(field_conditions) == 1:
                                # Single condition - use backward compatible format
                                field['condition'] = field_conditions[0]
                                print(f"  - RESULT: Field {i} has single condition: {field['condition']}")
                            else:
                                # Multiple conditions - use new format with logic
                                field['condition'] = {
                                    'logic': field_logic,
                                    'rules': field_conditions
                                }
                                print(f"  - RESULT: Field {i} has {len(field_conditions)} conditions with {field_logic} logic: {field['condition']}")
                    except ValueError:
                        field['condition'] = None
                        print(f"  - ERROR: Field {i} not found in conditional fields list!")
                else:
                    field['condition'] = None
                    print(f"  - RESULT: Field {i} is NOT conditional (condition set to null)")
                
                fields.append(field)
        
        # Common validation that applies to both approaches
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        if not fields:
            flash('At least one field is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
            
        # Serialize fields and update database
        serialized_fields = json.dumps(fields)
        update_data = {
            'title': title,
            'fields': serialized_fields
        }
        response = supabase.table('forms').update(update_data).eq('id', form_id).execute()
        if response.data:
            log_activity('update', 'form', form_id, f"Updated form title: {title}")
            flash('Form updated successfully.', 'success')
        else:
            if hasattr(response, 'error') and response.error:
                flash(f'Failed to update form: {response.error.message}', 'danger')
            else:
                log_activity('update', 'form', form_id, f"Updated form title: {title}")
                flash('Form updated successfully (no data returned). ', 'success')
    except Exception as e:
        print(f"Error updating form {form_id}: {str(e)}")
        flash(f'An error occurred while updating the form: {str(e)}', 'danger')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/api/create_patient_id', methods=['POST'])
@login_required
def create_patient_id():
    try:
        # Generate a unique patient ID using the current date and a sequential number
        current_date = datetime.now(EAT).strftime('%d%m%y')
        
        # Check for existing patient IDs with this date prefix to determine the next number
        response = supabase.table('patients').select('patient_id').like('patient_id', f"{current_date}-%").execute()
        
        # Determine the next sequential number
        next_num = 1
        if response.data:
            existing_numbers = []
            for record in response.data:
                patient_id = record['patient_id']
                # Extract number after the hyphen (format: DDMMYY-NNNN)
                try:
                    num = int(patient_id.split('-')[1])
                    existing_numbers.append(num)
                except (IndexError, ValueError):
                    continue
            
            if existing_numbers:
                next_num = max(existing_numbers) + 1
        
        # Format with leading zeros for a consistent 4-digit number (0001, 0002, etc.)
        # Changed from 3 digits to 4 digits to support up to 9999 patients per day
        patient_id = f"{current_date}-{next_num:04d}"
        
        # Create a new patient record in the patients table
        new_patient = {
            'patient_id': patient_id,
            'data': {}  # Initialize with empty data, will be populated on form submissions
        }
        
        insert_response = supabase.table('patients').insert(new_patient).execute()
        
        # Log the creation
        log_activity('create', 'patient', patient_id, f"Created new patient ID: {patient_id}")
        
        return jsonify({'patient_id': patient_id, 'success': True})
    
    except Exception as e:
        print(f"Error creating patient ID: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/search_patient_id', methods=['GET'])
@login_required
def search_patient_id():
    try:
        query = request.args.get('q', '')
        if not query or len(query) < 2:  # Require at least 2 characters for search
            return jsonify([])
        
        results = []
        seen_ids = set()  # To prevent duplicates
            
        # First search patients table by patient_id using pagination to search ALL patients
        print(f"Searching for patient ID pattern: {query}")
        patient_id_matches = fetch_all_pages(
            supabase.table('patients').select('patient_id, data, created_at').like('patient_id', f"%{query}%").order('created_at', desc=True),
            debug_name=f"patient_id_search_{query}"
        )
        
        # Add patient_id matches to results
        for patient in patient_id_matches:
            patient_id = patient['patient_id']
            if patient_id not in seen_ids and len(results) < 10:
                results.append(patient)
                seen_ids.add(patient_id)
                
        print(f"Found {len(patient_id_matches)} patient ID matches, added {len([p for p in results])} to results")
        
        # Name search - fetch ALL patients and search through them in chunks to find name matches
        if len(results) < 10:
            try:
                print(f"Starting name search for: {query}")
                # Get ALL patients using pagination, excluding those already found
                if seen_ids:
                    all_patients_query = supabase.table('patients').select('patient_id, data, created_at').not_('patient_id', 'in', list(seen_ids)).order('created_at', desc=True)
                else:
                    all_patients_query = supabase.table('patients').select('patient_id, data, created_at').order('created_at', desc=True)
                
                # Process patients in chunks to avoid memory issues
                page_size = 1000
                start = 0
                query_lower = query.lower()
                name_fields = ["Name", "Full Name", "First Name", "Last Name", "Patient Name"]
                
                while len(results) < 10:
                    try:
                        # Get next chunk of patients
                        chunk_response = all_patients_query.range(start, start + page_size - 1).execute()
                        patients_chunk = chunk_response.data
                        
                        if not patients_chunk:
                            print(f"No more patients to search at start={start}")
                            break
                            
                        print(f"Searching through {len(patients_chunk)} patients (chunk starting at {start})")
                        
                        # Search through this chunk for name matches
                        chunk_matches = 0
                        for patient in patients_chunk:
                            if len(results) >= 10:
                                break
                                
                            patient_id = patient['patient_id']
                            if patient_id in seen_ids:
                                continue
                                
                            patient_data = patient.get('data', {})
                            name_match = False
                            
                            # Check all forms in patient data
                            if isinstance(patient_data, dict):
                                for form_id, form_data in patient_data.items():
                                    if not isinstance(form_data, dict):
                                        continue
                                        
                                    # Check all fields in this form for name fields
                                    for field_name, field_value in form_data.items():
                                        if not field_value:
                                            continue
                                            
                                        # Check if this is a name field and contains our search term
                                        if field_name in name_fields and query_lower in str(field_value).lower():
                                            name_match = True
                                            patient['display_name'] = field_value
                                            break
                                            
                                    if name_match:
                                        break
                                        
                            if name_match:
                                results.append(patient)
                                seen_ids.add(patient_id)
                                chunk_matches += 1
                        
                        print(f"Found {chunk_matches} name matches in this chunk")
                        
                        # If we got less than a full page, we've reached the end
                        if len(patients_chunk) < page_size:
                            print(f"Reached end of patients table (got {len(patients_chunk)} < {page_size})")
                            break
                            
                        start += page_size
                        
                    except Exception as e:
                        print(f"Error processing chunk starting at {start}: {str(e)}")
                        break
                
                print(f"Name search completed. Total results: {len(results)}")
                
            except Exception as e:
                print(f"Error during paginated name search: {str(e)}")
        
        # If we still have fewer than 5 results, try searching form submissions as a fallback
        if len(results) < 5:
            try:
                print(f"Starting fallback search in form_submissions for: {query}")
                
                # Search in submissions by patient_id using pagination
                submission_id_matches = fetch_all_pages(
                    supabase.table('form_submissions').select('patient_id, data, created_at').like('patient_id', f"%{query}%").order('created_at', desc=True),
                    debug_name=f"submission_id_search_{query}"
                )
                
                # Process submission results
                for submission in submission_id_matches:
                    patient_id = submission['patient_id']
                    if patient_id not in seen_ids and len(results) < 10:
                        results.append({
                            'patient_id': patient_id,
                            'data': submission.get('data', {}),
                            'created_at': submission.get('created_at')
                        })
                        seen_ids.add(patient_id)
                
                print(f"Found {len(submission_id_matches)} submission ID matches")
                
                # Also search names in ALL submissions using chunked pagination
                if len(results) < 10:
                    print("Searching submission names using pagination...")
                    query_lower = query.lower()
                    name_fields = ["Name", "Full Name", "First Name", "Last Name", "Patient Name"]
                    
                    # Process submissions in chunks
                    page_size = 1000
                    start = 0
                    
                    while len(results) < 10:
                        try:
                            # Get next chunk of submissions
                            chunk_response = supabase.table('form_submissions').select('patient_id, data, created_at').order('created_at', desc=True).range(start, start + page_size - 1).execute()
                            submissions_chunk = chunk_response.data
                            
                            if not submissions_chunk:
                                print(f"No more submissions to search at start={start}")
                                break
                                
                            print(f"Searching through {len(submissions_chunk)} submissions (chunk starting at {start})")
                            
                            # Search through this chunk for name matches
                            chunk_matches = 0
                            for submission in submissions_chunk:
                                if len(results) >= 10:
                                    break
                                    
                                patient_id = submission['patient_id']
                                if patient_id in seen_ids:
                                    continue
                                    
                                # Check data for name fields
                                submission_data = submission.get('data', {})
                                name_match = False
                                display_name = None
                                
                                if isinstance(submission_data, dict):
                                    for field_name, field_value in submission_data.items():
                                        if not field_value:
                                            continue
                                            
                                        if field_name in name_fields and query_lower in str(field_value).lower():
                                            name_match = True
                                            display_name = field_value
                                            break
                                            
                                if name_match:
                                    result = {
                                        'patient_id': patient_id,
                                        'data': submission_data,
                                        'created_at': submission.get('created_at')
                                    }
                                    if display_name:
                                        result['display_name'] = display_name
                                        
                                    results.append(result)
                                    seen_ids.add(patient_id)
                                    chunk_matches += 1
                            
                            print(f"Found {chunk_matches} submission name matches in this chunk")
                            
                            # If we got less than a full page, we've reached the end
                            if len(submissions_chunk) < page_size:
                                print(f"Reached end of submissions table (got {len(submissions_chunk)} < {page_size})")
                                break
                                
                            start += page_size
                            
                        except Exception as e:
                            print(f"Error processing submissions chunk starting at {start}: {str(e)}")
                            break
                
                print(f"Fallback search completed. Total results: {len(results)}")
                
            except Exception as e:
                print(f"Error searching form submissions: {str(e)}")
        
        # Extract and add display_name for any results that don't have it yet
        name_fields = ["Name", "Full Name", "First Name", "Last Name", "Patient Name"]
        for patient in results:
            # Skip if display name is already set
            if 'display_name' in patient:
                continue
                
            # Try to find a name field in the patient data
            patient_data = patient.get('data', {})
            display_name = None
            
            # Search through all forms in patient data
            if isinstance(patient_data, dict):
                # First, search in all form data
                for form_data in patient_data.values():
                    if not isinstance(form_data, dict):
                        continue
                        
                    # Check each form for name fields
                    for field_name, field_value in form_data.items():
                        if field_name in name_fields and field_value:
                            display_name = field_value
                            break
                    
                    if display_name:
                        break
            
            # Add display name if found
            if display_name:
                patient['display_name'] = display_name
        
        # Return the results
        return jsonify(results)
    
    except Exception as e:
        print(f"Error searching for patient: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patient_preview/<patient_id>')
@login_required  
def get_patient_preview(patient_id):
    # Get optional project_id parameter to filter forms by project
    project_id = request.args.get('project_id')
    try:
        # Get patient data from patients table
        patient_response = supabase.table('patients').select('*').eq('patient_id', patient_id).execute()
        
        # Initialize result structure
        result = {
            'patient_record': {
                'patient_id': patient_id,
                'data': {},
                'created_at': None,
                'created_at_eat': None
            },
            'form_details': {}
        }
        
        if not patient_response.data:
            # Try to get data from form_submissions (legacy data)
            submissions_response = supabase.table('form_submissions').select('*, forms(id, title, fields, project_id, projects(name))').eq('patient_id', patient_id).order('created_at').execute()
            
            if not submissions_response.data:
                return jsonify({'error': 'Patient not found'}), 404
            
            # Reconstruct patient data from submissions
            submissions = submissions_response.data
            
            # Use the earliest submission date as patient creation date
            if submissions and 'created_at' in submissions[0]:
                created_at = submissions[0]['created_at']
                result['patient_record']['created_at'] = created_at
                # Convert to EAT timezone for display
                try:
                    created_at_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    eat_dt = created_at_dt.astimezone(EAT)
                    result['patient_record']['created_at_eat'] = eat_dt.isoformat()
                except Exception as e:
                    print(f"Error converting timestamp: {str(e)}")
            
            # Group form data by form ID, filtered by project if specified
            for submission in submissions:
                form = submission.get('forms', {})
                form_id = form.get('id')
                form_project_id = form.get('project_id')
                
                if not form_id:
                    continue
                
                # If project filtering is active, only include forms from the specified project
                if project_id and form_project_id != project_id:
                    print(f"Patient preview (legacy): Excluding form {form_id} (project {form_project_id}) - not in target project {project_id}")
                    continue
                
                print(f"Patient preview (legacy): Including form {form_id} from project {form_project_id}")
                
                # Create form details entry if we haven't seen this form before
                if form_id not in result['form_details']:
                    # Check if this is a registration form (first form in project)
                    is_registration_form = get_form_is_first(form_id) if form_id else False
                    
                    form_title = form.get('title', 'Unknown Form')
                    if is_registration_form:
                        form_title = f"{form_title} (Registration)"
                    
                    result['form_details'][form_id] = {
                        'title': form_title,
                        'field_order': []  # Will populate with field names in the order they appear
                    }
                    
                    # Get field order from form definition if available
                    if 'fields' in form and isinstance(form['fields'], list):
                        field_order = [field.get('label') for field in form['fields'] if 'label' in field]
                        result['form_details'][form_id]['field_order'] = field_order
                
                # Extract data from this submission
                submission_data = submission.get('data', {})
                
                # Add to patient record data under this form ID
                if form_id not in result['patient_record']['data']:
                    result['patient_record']['data'][form_id] = {}
                
                # Merge this submission's data with existing data for this form
                result['patient_record']['data'][form_id].update(submission_data)
            
            return jsonify(result)
        
        # Patient found in patients table - use the data from there
        patient = patient_response.data[0]
        
        # Format patient record
        result['patient_record'] = {
            'patient_id': patient_id,
            'data': patient.get('data', {}),
            'created_at': patient.get('created_at'),
            'project_id': patient.get('project_id')
        }
        
        # Convert created_at to EAT timezone if available
        if 'created_at' in patient and patient['created_at']:
            try:
                created_at_dt = datetime.fromisoformat(patient['created_at'].replace('Z', '+00:00'))
                eat_dt = created_at_dt.astimezone(EAT)
                result['patient_record']['created_at_eat'] = eat_dt.isoformat()
            except Exception as e:
                print(f"Error converting timestamp: {str(e)}")
        
        # Get form details for each form ID in the patient data, filtered by project if specified
        form_ids = patient.get('data', {}).keys()
        
        # If project_id is specified, get all form IDs that belong to that project for filtering
        project_form_ids = set()
        if project_id:
            try:
                project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
                if project_forms_response.data:
                    project_form_ids = {form['id'] for form in project_forms_response.data}
                    print(f"Patient preview: Filtering to show only forms from project {project_id}: {project_form_ids}")
            except Exception as e:
                print(f"Error fetching project forms for filtering: {str(e)}")
        
        # Create filtered patient data and form details based on project
        filtered_patient_data = {}
        
        for form_id in form_ids:
            # Handle special case for centralized registration data (always include)
            if form_id == 'registration':
                # Always include registration data
                filtered_patient_data['registration'] = patient.get('data', {}).get('registration', {})
                result['form_details']['registration'] = {
                    'title': 'Patient Registration',
                    'field_order': [
                        'Name',
                        'Age (Years)', 
                        'Gender',
                        'Region',
                        'District', 
                        'Ward',
                        'Phone Number'
                    ]
                }
                continue
            
            # Handle regular form IDs - filter by project if specified
            form_response = supabase.table('forms').select('id, title, fields, project_id, projects(name)').eq('id', form_id).execute()
            
            if form_response.data:
                form = form_response.data[0]
                form_project_id = form.get('project_id')
                
                # If project filtering is active, only include forms from the specified project
                if project_id and form_project_id != project_id:
                    print(f"Patient preview: Excluding form {form_id} (project {form_project_id}) - not in target project {project_id}")
                    continue
                
                # Include this form's data
                filtered_patient_data[form_id] = patient.get('data', {}).get(form_id, {})
                
                # Add form details to the form_details map
                result['form_details'][form_id] = {
                    'title': form.get('title', 'Unknown Form'),
                    'field_order': []
                }
                
                # Extract field order from form definition if available
                if 'fields' in form:
                    fields_data = form['fields']
                    if isinstance(fields_data, str):
                        try:
                            fields_data = json.loads(fields_data)
                        except:
                            fields_data = []
                    
                    if isinstance(fields_data, list):
                        field_order = [field.get('label') for field in fields_data if 'label' in field]
                        result['form_details'][form_id]['field_order'] = field_order
                        
                print(f"Patient preview: Including form {form_id} from project {form_project_id}")
        
        # Update the patient record data to only include filtered forms
        result['patient_record']['data'] = filtered_patient_data
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error getting patient preview: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/patient/<patient_id>/delete', methods=['POST'])
@login_required
def delete_patient(patient_id):
    # Only admins can delete patients
    if not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    try:
        print(f"Attempting to delete patient: {patient_id}")
        
        # Start a transaction by getting connection
        # (Supabase doesn't support true transactions via API, so we handle rollback manually)
        deletion_successful = False
        deleted_submissions = 0
        patient_record_deleted = False
        
        # 1. First get all submissions for this patient
        submissions_response = supabase.table('form_submissions').select('id').eq('patient_id', patient_id).execute()
        
        # 2. Also check if patient record exists
        patient_response = supabase.table('patients').select('patient_id').eq('patient_id', patient_id).execute()
        patient_exists = len(patient_response.data) > 0
        
        if not submissions_response.data and not patient_exists:
            print(f"No records found for patient {patient_id}")
            return jsonify({'error': 'Patient not found in any records'}), 404
        
        # 3. Delete all submissions for this patient
        if submissions_response.data:
            submission_ids = [sub['id'] for sub in submissions_response.data]
            print(f"Found {len(submission_ids)} submissions to delete")
            
            try:
                # Delete submissions in batches to avoid hitting API limits
                batch_size = 50
                for i in range(0, len(submission_ids), batch_size):
                    batch = submission_ids[i:i + batch_size]
                    delete_response = supabase.table('form_submissions').delete().in_('id', batch).execute()
                    print(f"Deleted batch of {len(batch)} submissions")
                    deleted_submissions += len(batch)
                
                deletion_successful = True
            except Exception as e:
                print(f"Error deleting patient submissions: {str(e)}")
                return jsonify({'error': f'Failed to delete patient submissions: {str(e)}'}), 500
        else:
            # No submissions but patient might still exist
            deletion_successful = True
        
        # 4. Delete the patient record from patients table
        if patient_exists:
            try:
                patient_delete_response = supabase.table('patients').delete().eq('patient_id', patient_id).execute()
                patient_record_deleted = True
                print(f"Deleted patient record for {patient_id}")
            except Exception as e:
                print(f"Error deleting patient record: {str(e)}")
                return jsonify({'error': f'Failed to delete patient record: {str(e)}'}), 500
        
        # 5. Log the deletion
        if deletion_successful:
            log_details = f"Deleted patient {patient_id} with {deleted_submissions} form submissions"
            if patient_record_deleted:
                log_details += " and patient record"
            log_activity('delete', 'patient', patient_id, log_details)
            
            return jsonify({
                'success': True,
                'message': f'Patient {patient_id} completely deleted ({deleted_submissions} submissions, patient record: {patient_record_deleted})',
                'deleted_submissions': deleted_submissions,
                'patient_record_deleted': patient_record_deleted
            })
        else:
            return jsonify({'error': 'Failed to delete patient - unknown error'}), 500
            
    except Exception as e:
        print(f"Error in patient deletion: {str(e)}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reset_password/<user_id>', methods=['POST'])
@login_required
def reset_user_password(user_id):
    # Ensure user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to reset passwords.', 'danger')
        return redirect(url_for('index'))
    
    new_password = request.form.get('new_password')
    if not new_password:
        flash('Password cannot be empty', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get user details to ensure they exist
    response = supabase.table('users').select('*').eq('id', user_id).execute()
    if not response.data:
        flash('User not found', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = response.data[0]
    
    # Hash the new password
    hashed_password = generate_password_hash(new_password)
    
    # Update the user's password
    supabase.table('users').update({'password': hashed_password}).eq('id', user_id).execute()
    
    # Log password reset
    log_activity('update', 'user', user_id, f"Password reset for user: {user['username']}")
    
    flash(f"Password for {user['username']} has been reset successfully", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/api/form/<form_id>/fields')
@login_required
def get_form_fields(form_id):
    """Get all fields for a specific form for the dataset filter dropdown"""
    try:
        # Get form details to extract fields
        form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
        
        if not form_response.data:
            return jsonify({'error': 'Form not found'}), 404
        
        form = form_response.data[0]
        project_id = form.get('project_id')
        
        # Parse the fields JSON string into Python objects if needed
        fields = []
        if isinstance(form['fields'], str):
            try:
                parsed_fields = json.loads(form['fields'])
                fields = [field.get('label') for field in parsed_fields if isinstance(field, dict) and 'label' in field]
            except Exception as e:
                print(f"Error parsing form fields in get_form_fields: {str(e)}")
        elif isinstance(form['fields'], list):
            fields = [field.get('label') for field in form['fields'] if isinstance(field, dict) and 'label' in field]
        
        # For consistency with dataset_view, also fetch fields from the same project
        # that might not be directly in the form definition
        if project_id:
            # Get all forms from this project
            project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
            if project_forms_response.data:
                project_form_ids = [form['id'] for form in project_forms_response.data]
                
                # Only add this part if this is not the only form in the project
                if len(project_form_ids) > 1:
                    print(f"Getting fields from other forms in project {project_id}")
                    # Get fields from other forms in the same project
                    for project_form_id in project_form_ids:
                        if project_form_id != form_id:  # Skip the current form
                            other_form_response = supabase.table('forms').select('fields').eq('id', project_form_id).execute()
                            if other_form_response.data:
                                other_form = other_form_response.data[0]
                                other_fields_json = other_form.get('fields', '[]')
                                try:
                                    if isinstance(other_fields_json, str):
                                        other_parsed_fields = json.loads(other_fields_json)
                                    else:
                                        other_parsed_fields = other_fields_json
                                    
                                    if isinstance(other_parsed_fields, list):
                                        other_fields = [field.get('label') for field in other_parsed_fields 
                                                     if isinstance(field, dict) and 'label' in field]
                                        
                                        # Add only fields that don't already exist
                                        for field in other_fields:
                                            if field not in fields:
                                                fields.append(field)
                                except Exception as e:
                                    print(f"Error parsing fields from other form {project_form_id}: {e}")
        
        return jsonify({'fields': fields, 'project_id': project_id})
        
    except Exception as e:
        print(f"Error getting form fields: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/form/<form_id>/field/<field_name>/values')
@login_required
def get_field_values(form_id, field_name):
    """Get possible values for a specific field in a form for the dataset filter dropdown"""
    try:
        # URL decode the field name since it might contain spaces
        field_name = urllib.parse.unquote(field_name)
        
        # First verify that the form exists and get its project_id
        form_response = supabase.table('forms').select('project_id').eq('id', form_id).execute()
        
        if not form_response.data:
            return jsonify({'error': 'Form not found'}), 404
            
        project_id = form_response.data[0]['project_id']
        
        # Get submissions for this form with this field
        field_values = set()
        
        # Normalized field name for comparison
        normalized_field = field_name.lower().strip().replace(' ', '_')
        
        # Fetch submissions for this form using pagination
        submissions_data = []
        page_size = 1000
        start = 0
        
        while True:
            try:
                page_response = supabase.table('form_submissions').select('data').eq('form_id', form_id).range(start, start + page_size - 1).execute()
                page_data = page_response.data
                
                if not page_data:
                    break
                    
                submissions_data.extend(page_data)
                
                if len(page_data) < page_size:
                    break
                    
                start += page_size
            except Exception as e:
                print(f"Field values: Error fetching submissions page starting at {start}: {str(e)}")
                break
        
        if submissions_data:
            for submission in submissions_data:
                if submission.get('data'):
                    # Look through normalized field names to find a match
                    for key, value in submission['data'].items():
                        if key.lower().strip().replace(' ', '_') == normalized_field:
                            # Handle different value types
                            if isinstance(value, list):
                                # For multi-select fields like checkboxes
                                for item in value:
                                    field_values.add(str(item))
                            else:
                                field_values.add(str(value))
        
        return jsonify({'values': sorted(list(field_values)), 'project_id': project_id})
    
    except Exception as e:
        print(f"Error getting field values: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/form_waitlist/<form_id>', methods=['GET'])
@login_required
def form_waitlist(form_id):
    """API endpoint to get the waitlist for a specific form.
    
    This endpoint returns patients who:
    1. Have not yet completed the current form
    2. For forms beyond the first, have completed the previous form
    3. Were created today (in East African Time)
    
    Returns:
        JSON: List of patient records with eligibility status
    """
    try:
        print(f"Fetching waitlist for form: {form_id}")
        
        # Calculate today's date range in East African Time (GMT+3)
        now_eat = datetime.now(EAT)
        today_start = now_eat.replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = now_eat.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Convert to UTC for database query (Supabase stores timestamps in UTC)
        today_start_utc = today_start.astimezone(timezone.utc)
        today_end_utc = today_end.astimezone(timezone.utc)
        
        print(f"Filtering patients created today in EAT: {today_start.strftime('%Y-%m-%d %H:%M:%S')} to {today_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"UTC range for database query: {today_start_utc.isoformat()} to {today_end_utc.isoformat()}")
        
        # Get form details
        form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
        if not form_response.data:
            return jsonify({'error': 'Form not found'}), 404
            
        form = form_response.data[0]
        
        # Get the project
        project_response = supabase.table('projects').select('*').eq('id', form['project_id']).execute()
        if not project_response.data:
            return jsonify({'error': 'Project not found'}), 404
            
        project = project_response.data[0]
            
        # Get all forms in this project to determine order
        forms_query = supabase.table('forms').select('*').eq('project_id', project['id']).order('created_at')
        project_forms = fetch_all_pages(forms_query, debug_name=f"waitlist_project_{project['id']}_forms")
        
        # Map form IDs to their positions in the sequence
        form_indices = {f['id']: idx for idx, f in enumerate(project_forms)}
        current_form_index = form_indices.get(form_id, 0)
        
        # Get patients created today using pagination with date filtering
        patients = []
        page_size = 1000
        start = 0
        
        while True:
            try:
                # Filter patients to only those created today in EAT
                page_response = supabase.table('patients')\
                    .select('*')\
                    .gte('created_at', today_start_utc.isoformat())\
                    .lte('created_at', today_end_utc.isoformat())\
                    .range(start, start + page_size - 1)\
                    .execute()
                page_data = page_response.data
                
                if not page_data:
                    break
                    
                patients.extend(page_data)
                
                if len(page_data) < page_size:
                    break
                    
                start += page_size
            except Exception as e:
                print(f"Waitlist: Error fetching patients page starting at {start}: {str(e)}")
                break
        
        # Get all submissions for tracking completed forms using pagination
        submissions = []
        start = 0
        
        while True:
            try:
                page_response = supabase.table('form_submissions').select('form_id, patient_id').range(start, start + page_size - 1).execute()
                page_data = page_response.data
                
                if not page_data:
                    break
                    
                submissions.extend(page_data)
                
                if len(page_data) < page_size:
                    break
                    
                start += page_size
            except Exception as e:
                print(f"Waitlist: Error fetching submissions page starting at {start}: {str(e)}")
                break
        
        # Create a set of (patient_id, form_id) tuples for quick lookup
        completed_forms = set([(sub['patient_id'], sub['form_id']) for sub in submissions])
        
        result = []
        
        for patient in patients:
            patient_id = patient['patient_id']
            
            # Skip patients who already have completed this form
            if (patient_id, form_id) in completed_forms:
                continue
            
            # For forms beyond the first, check if the patient completed the previous form
            is_eligible = True
            patient_display_name = None
            last_completed_form = None
            
            if current_form_index > 0 and project_forms:
                # Find the previous form
                prev_form_id = project_forms[current_form_index - 1]['id'] if current_form_index - 1 < len(project_forms) else None
                
                if prev_form_id and not (patient_id, prev_form_id) in completed_forms:
                    is_eligible = False
                
                # Find the last completed form for this patient
                patient_completed_forms = [(idx, f['id']) for f in project_forms 
                                          for idx in [form_indices.get(f['id'])]
                                          if (patient_id, f['id']) in completed_forms]
                
                if patient_completed_forms:
                    last_idx, last_form_id = max(patient_completed_forms, key=lambda x: x[0])
                    last_completed_form = next((f['title'] for f in project_forms if f['id'] == last_form_id), None)
            
            # Try to get patient name from centralized registration data first
            if patient.get('data'):
                # First priority: centralized registration data
                registration_data = patient['data'].get('registration', {})
                if isinstance(registration_data, dict) and registration_data.get('Name'):
                    patient_display_name = registration_data['Name']
                else:
                    # Fallback: look through all form data for name fields
                    for form_data in patient['data'].values():
                        if isinstance(form_data, dict):
                            # Look for common name fields in form data
                            for field in ['Full Name', 'Name', 'Patient Name', 'First Name']:
                                if field in form_data and form_data[field]:
                                    patient_display_name = form_data[field]
                                break
                    if patient_display_name:
                        break
            
            # Get additional patient info from centralized registration
            age = None
            gender = None
            phone = None
            
            if patient.get('data'):
                registration_data = patient['data'].get('registration', {})
                if isinstance(registration_data, dict):
                    age = registration_data.get('Age (Years)')
                    gender = registration_data.get('Gender')
                    phone = registration_data.get('Phone Number')
                    
                    print(f"Waitlist: Patient {patient_id} - Name: {patient_display_name}, Age: {age}, Gender: {gender}")
            
            result.append({
                'patient_id': patient_id,
                'display_name': patient_display_name,
                'age': age,
                'gender': gender,
                'phone': phone,
                'last_form_completed': last_completed_form,
                'is_eligible': is_eligible
            })
        
        return jsonify({'patients': result})
    except Exception as e:
        print(f"Error in form_waitlist: {str(e)}")
        traceback.print_exc()  # Print the full error traceback
        return jsonify({'error': str(e)}), 500

@app.route('/api/form/<form_id>/toggle_waitlist', methods=['POST'])
@login_required
def toggle_form_waitlist(form_id):
    """API endpoint to toggle the visibility of the waitlist for a specific form.
    
    This endpoint allows admins to control which forms display the waitlist.
    
    Returns:
        JSON: Updated waitlist visibility status
    """
    # Only admins can toggle waitlist visibility
    if not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
        
    try:
        # Get the form details
        form_response = supabase.table('forms').select('*').eq('id', form_id).execute()
        if not form_response.data:
            return jsonify({'error': 'Form not found'}), 404
            
        form = form_response.data[0]
        
        # Toggle the show_waitlist field (if it doesn't exist, default to False and then toggle)
        current_status = form.get('show_waitlist', False)
        new_status = not current_status
        
        # Update the form in the database
        update_response = supabase.table('forms').update({'show_waitlist': new_status}).eq('id', form_id).execute()
        
        if not update_response.data:
            return jsonify({'error': 'Failed to update form'}), 500
            
        # Log the action
        action_type = "enabled" if new_status else "disabled"
        log_activity('update', 'form', form_id, f"Waitlist {action_type} for form: {form.get('title', 'Unknown')}")
        
        return jsonify({
            'success': True,
            'show_waitlist': new_status,
            'message': f"Waitlist has been {'enabled' if new_status else 'disabled'} for this form"
        })
        
    except Exception as e:
        print(f"Error toggling waitlist visibility: {str(e)}")
        traceback.print_exc()  # Print the full error traceback
        return jsonify({'error': str(e)}), 500

@app.route('/api/form/<form_id>/answers/<patient_id>', methods=['GET'])
@login_required
def get_form_answers(form_id, patient_id):
    """
    Returns the latest submitted answers for a given form and patient.
    Output: { field_label: value, ... }
    """
    try:
        # Get the latest submission for this form and patient
        response = supabase.table('form_submissions')\
            .select('*')\
            .eq('form_id', form_id)\
            .eq('patient_id', patient_id)\
            .order('created_at', desc=True)\
            .limit(1)\
            .execute()
        if not response.data:
            return jsonify({}), 200  # No previous answers, return empty dict
        submission = response.data[0]
        answers = submission.get('data', {})
        return jsonify(answers)
    except Exception as e:
        print(f"Error fetching form answers for form {form_id}, patient {patient_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/statistics', methods=['GET'])
@login_required
def admin_statistics():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Get date range parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    camp_id = request.args.get('camp_id')
    
    # Handle camp filtering - if camp_id is provided, override start_date and end_date
    selected_camp = None
    if camp_id:
        try:
            camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
            if camp_response.data:
                selected_camp = camp_response.data[0]
                start_date = selected_camp['start_date']
                end_date = selected_camp['end_date']
                print(f"Statistics: Using camp '{selected_camp['name']}' dates: {start_date} to {end_date}")
        except Exception as e:
            print(f"Statistics: Error fetching camp details: {str(e)}")
            # If camp lookup fails, continue with original dates
    
    # Log access
    log_details = "Viewed statistics dashboard"
    if camp_id and selected_camp:
        log_details += f" - Camp: {selected_camp['name']}"
    elif start_date or end_date:
        log_details += f" - Date range: {start_date or 'start'} to {end_date or 'end'}"
    log_activity('view', 'statistics', None, log_details)
    
    print(f"Statistics dashboard accessed with date range: {start_date} to {end_date}")
    
    # Build date filter for queries
    date_filter = {}
    if start_date:
        date_filter['start'] = start_date
    if end_date:
        # Add 1 day to end_date to make it inclusive
        try:
            end_date_dt = datetime.strptime(end_date, '%Y-%m-%d')
            inclusive_end_date = (end_date_dt + timedelta(days=1)).strftime('%Y-%m-%d')
            date_filter['end'] = inclusive_end_date
        except ValueError:
            print(f"Invalid end date format: {end_date}")
            date_filter['end'] = None
    
    # 1. Get Total Patient IDs Created (from patients table - all patient records)
    patient_ids_query = supabase.table('patients').select('patient_id, created_at')
    if date_filter.get('start'):
        patient_ids_query = patient_ids_query.gte('created_at', date_filter['start'])
    if date_filter.get('end'):
        patient_ids_query = patient_ids_query.lt('created_at', date_filter['end'])
    
    try:
        patient_ids_data = fetch_all_pages(patient_ids_query, debug_name="patient_ids_created")
        total_patient_ids_created = len(patient_ids_data)
    except Exception as e:
        print(f"Error fetching patient IDs created: {str(e)}")
        total_patient_ids_created = 0
    
    # 2. Get Total Registered Patients (patients with centralized registration data)
    registered_patients = set()
    registered_patients_query = supabase.table('patients').select('patient_id, created_at, data')
    if date_filter.get('start'):
        registered_patients_query = registered_patients_query.gte('created_at', date_filter['start'])
    if date_filter.get('end'):
        registered_patients_query = registered_patients_query.lt('created_at', date_filter['end'])
    
    try:
        registered_patients_data = fetch_all_pages(registered_patients_query, debug_name="registered_patients")
        for patient in registered_patients_data:
            # Check if patient has registration data in the centralized system
            if (patient.get('data') and 
                patient['data'].get('registration') and 
                patient.get('patient_id')):
                registered_patients.add(patient['patient_id'])
    except Exception as e:
        print(f"Error fetching registered patients: {str(e)}")
    
    total_registered_patients = len(registered_patients)
    print(f"Found {total_registered_patients} patients with centralized registration data")
    
    # 3. Get Patients Attended (patients with ANY project form submissions - all forms are now medical care)
    attended_patients = set()
    attended_query = supabase.table('form_submissions').select('patient_id, created_at')
    if date_filter.get('start'):
        attended_query = attended_query.gte('created_at', date_filter['start'])
    if date_filter.get('end'):
        attended_query = attended_query.lt('created_at', date_filter['end'])
        
    try:
        attended_data = fetch_all_pages(attended_query, debug_name="attended_submissions")
        for submission in attended_data:
            if submission.get('patient_id'):
                attended_patients.add(submission['patient_id'])
    except Exception as e:
        print(f"Error fetching attended submissions: {str(e)}")
    
    total_patients_attended = len(attended_patients)
    print(f"Found {total_patients_attended} patients who received medical care (form submissions)")
    
    # 4. Calculate Difference (registered but not attended)
    registered_but_not_attended = registered_patients - attended_patients
    difference = len(registered_but_not_attended)
    
    # Calculate percentages
    attendance_rate = 0
    if total_registered_patients > 0:
        attendance_rate = (total_patients_attended / total_registered_patients) * 100
    
    registration_rate = 0
    if total_patient_ids_created > 0:
        registration_rate = (total_registered_patients / total_patient_ids_created) * 100
    
    print(f"Statistics calculated:")
    print(f"  - Patient IDs Created: {total_patient_ids_created}")
    print(f"  - Registered Patients: {total_registered_patients}")
    print(f"  - Patients Attended: {total_patients_attended}")
    print(f"  - Difference (Registered but not attended): {difference}")
    print(f"  - Attendance Rate: {attendance_rate:.1f}%")
    print(f"  - Registration Rate: {registration_rate:.1f}%")
    
    # 5. Get Project-Based Statistics
    project_statistics = []
    try:
        # Get all projects
        all_projects_data = fetch_all_pages(
            supabase.table('projects').select('*').order('name'),
            debug_name="projects_for_statistics"
        )
        
        for project in all_projects_data:
            project_id = project['id']
            project_name = project['name']
            
            # Get all forms for this project
            project_forms_response = supabase.table('forms').select('id').eq('project_id', project_id).execute()
            if not project_forms_response.data:
                continue
                
            project_form_ids = [form['id'] for form in project_forms_response.data]
            
            # Get unique patients who had submissions in this project
            project_query = supabase.table('form_submissions').select('patient_id, created_at').in_('form_id', project_form_ids)
            if date_filter.get('start'):
                project_query = project_query.gte('created_at', date_filter['start'])
            if date_filter.get('end'):
                project_query = project_query.lt('created_at', date_filter['end'])
            
            project_submissions = fetch_all_pages(project_query, debug_name=f"project_{project_id}_submissions")
            project_patients = set()
            for submission in project_submissions:
                if submission.get('patient_id'):
                    project_patients.add(submission['patient_id'])
            
            patients_seen_count = len(project_patients)
            
            # Calculate percentage of total attended patients
            percentage_of_attended = 0
            if total_patients_attended > 0:
                percentage_of_attended = (patients_seen_count / total_patients_attended) * 100
            
            project_statistics.append({
                'name': project_name,
                'patients_seen': patients_seen_count,
                'percentage': percentage_of_attended
            })
            
            print(f"  - {project_name}: {patients_seen_count} patients seen ({percentage_of_attended:.1f}% of total)")
            
    except Exception as e:
        print(f"Error calculating project statistics: {str(e)}")
        project_statistics = []
    
    # Get all camps for filter dropdown
    camps_data = fetch_all_pages(
        supabase.table('camps').select('*').order('start_date', desc=True),
        debug_name="camps_for_statistics_filter"
    )
    
    return render_template('admin_statistics.html',
                         total_patient_ids_created=total_patient_ids_created,
                         total_registered_patients=total_registered_patients,
                         total_patients_attended=total_patients_attended,
                         difference=difference,
                         attendance_rate=attendance_rate,
                         registration_rate=registration_rate,
                         project_statistics=project_statistics,
                         camps=camps_data,
                         selected_camp=camp_id,
                         selected_camp_name=selected_camp['name'] if selected_camp else None,
                         start_date=start_date,
                         end_date=end_date)

# =======================
# CAMP MANAGEMENT ROUTES
# =======================

@app.route('/admin/camps')
@login_required
def camps_list():
    """List all camps (admin only)"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Log access
    log_activity('view', 'camps', None, 'Viewed camps list')
    
    try:
        # Get all camps ordered by start_date
        camps_data = fetch_all_pages(
            supabase.table('camps').select('*, users(username)').order('start_date', desc=True),
            debug_name="camps_list"
        )
        
        print(f"Found {len(camps_data)} camps")
        
        return render_template('camps_list.html', camps=camps_data)
        
    except Exception as e:
        print(f"Error fetching camps: {str(e)}")
        flash(f'Error loading camps: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/camps/new', methods=['GET', 'POST'])
@login_required
def create_camp():
    """Create a new camp (admin only)"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name', '').strip()
            start_date = request.form.get('start_date', '').strip()
            end_date = request.form.get('end_date', '').strip()
            location = request.form.get('location', '').strip()
            description = request.form.get('description', '').strip()
            
            # Validate required fields
            if not name:
                flash('Camp name is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Create New Camp',
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not start_date:
                flash('Start date is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Create New Camp',
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not end_date:
                flash('End date is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Create New Camp',
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not location:
                flash('Location is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Create New Camp',
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            # Validate date order
            try:
                start_dt = datetime.strptime(start_date, '%Y-%m-%d')
                end_dt = datetime.strptime(end_date, '%Y-%m-%d')
                if start_dt > end_dt:
                    flash('Start date must be before or equal to end date.', 'error')
                    return render_template('camp_form.html', 
                                         title='Create New Camp',
                                         name=name, start_date=start_date, end_date=end_date,
                                         location=location, description=description)
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return render_template('camp_form.html', 
                                     title='Create New Camp',
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            # Create camp record
            camp_id = str(uuid.uuid4())
            camp_data = {
                'id': camp_id,
                'name': name,
                'start_date': start_date,
                'end_date': end_date,
                'location': location,
                'description': description if description else None,
                'created_by': current_user.id
            }
            
            # Insert into database
            response = supabase.table('camps').insert(camp_data).execute()
            
            if response.data:
                log_activity('create', 'camp', camp_id, f'Created camp: {name}')
                flash(f'Camp "{name}" created successfully!', 'success')
                return redirect(url_for('camps_list'))
            else:
                flash('Failed to create camp. Please try again.', 'error')
                
        except Exception as e:
            print(f"Error creating camp: {str(e)}")
            flash(f'Error creating camp: {str(e)}', 'error')
    
    # GET request - show form
    return render_template('camp_form.html', title='Create New Camp')

@app.route('/admin/camps/edit/<camp_id>', methods=['GET', 'POST'])
@login_required
def edit_camp(camp_id):
    """Edit an existing camp (admin only)"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get camp details
        camp_response = supabase.table('camps').select('*').eq('id', camp_id).execute()
        if not camp_response.data:
            flash('Camp not found.', 'error')
            return redirect(url_for('camps_list'))
        
        camp = camp_response.data[0]
        
        if request.method == 'POST':
            # Get form data
            name = request.form.get('name', '').strip()
            start_date = request.form.get('start_date', '').strip()
            end_date = request.form.get('end_date', '').strip()
            location = request.form.get('location', '').strip()
            description = request.form.get('description', '').strip()
            
            # Validate required fields
            if not name:
                flash('Camp name is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Edit Camp', camp=camp,
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not start_date:
                flash('Start date is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Edit Camp', camp=camp,
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not end_date:
                flash('End date is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Edit Camp', camp=camp,
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            if not location:
                flash('Location is required.', 'error')
                return render_template('camp_form.html', 
                                     title='Edit Camp', camp=camp,
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            # Validate date order
            try:
                start_dt = datetime.strptime(start_date, '%Y-%m-%d')
                end_dt = datetime.strptime(end_date, '%Y-%m-%d')
                if start_dt > end_dt:
                    flash('Start date must be before or equal to end date.', 'error')
                    return render_template('camp_form.html', 
                                         title='Edit Camp', camp=camp,
                                         name=name, start_date=start_date, end_date=end_date,
                                         location=location, description=description)
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return render_template('camp_form.html', 
                                     title='Edit Camp', camp=camp,
                                     name=name, start_date=start_date, end_date=end_date,
                                     location=location, description=description)
            
            # Update camp record
            update_data = {
                'name': name,
                'start_date': start_date,
                'end_date': end_date,
                'location': location,
                'description': description if description else None
            }
            
            # Update in database
            response = supabase.table('camps').update(update_data).eq('id', camp_id).execute()
            
            if response.data:
                log_activity('update', 'camp', camp_id, f'Updated camp: {name}')
                flash(f'Camp "{name}" updated successfully!', 'success')
                return redirect(url_for('camps_list'))
            else:
                flash('Failed to update camp. Please try again.', 'error')
        
        # GET request - show form with current data
        return render_template('camp_form.html', title='Edit Camp', camp=camp)
        
    except Exception as e:
        print(f"Error editing camp: {str(e)}")
        flash(f'Error editing camp: {str(e)}', 'error')
        return redirect(url_for('camps_list'))

@app.route('/admin/camps/delete/<camp_id>', methods=['POST'])
@login_required
def delete_camp(camp_id):
    """Delete a camp (admin only)"""
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get camp details first for logging
        camp_response = supabase.table('camps').select('name').eq('id', camp_id).execute()
        camp_name = camp_response.data[0]['name'] if camp_response.data else 'Unknown'
        
        # Delete the camp
        response = supabase.table('camps').delete().eq('id', camp_id).execute()
        
        if response.data:
            log_activity('delete', 'camp', camp_id, f'Deleted camp: {camp_name}')
            flash(f'Camp "{camp_name}" deleted successfully!', 'success')
        else:
            flash('Failed to delete camp. Please try again.', 'error')
            
    except Exception as e:
        print(f"Error deleting camp: {str(e)}")
        flash(f'Error deleting camp: {str(e)}', 'error')
    
    return redirect(url_for('camps_list'))

@app.route('/api/camps')
@login_required
def get_camps_api():
    """API endpoint to get all camps for use in filter dropdowns"""
    try:
        # Get all camps ordered by start_date
        camps_data = fetch_all_pages(
            supabase.table('camps').select('id, name, start_date, end_date, location').order('start_date', desc=True),
            debug_name="camps_api"
        )
        
        return jsonify({
            'success': True,
            'camps': camps_data
        })
        
    except Exception as e:
        print(f"Error fetching camps API: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/reports')
@login_required
def reports():
    """Display the reports page for users (not admins)"""
    if current_user.is_admin:
        flash('Reports section is for regular users only.', 'info')
        return redirect(url_for('admin_dashboard'))
    
    # Get all projects for the dropdown
    projects_response = supabase.table('projects').select('*').order('name').execute()
    projects = projects_response.data if projects_response.data else []
    
    log_activity('view', 'reports', None, "Viewed reports page")
    
    return render_template('reports.html', projects=projects)

@app.route('/api/report_types/<project_id>')
@login_required  
def get_report_types_for_programme(project_id):
    """Get available report types for a specific programme"""
    try:
        # Get programme details to determine available report types
        programme_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if not programme_response.data:
            return jsonify({'report_types': []})
        
        programme_name = programme_response.data[0]['name'].upper()
        
        # Define report types based on programme
        report_types = []
        
        # Always add doctor reports and programme summary
        report_types.append({'value': 'doctor', 'label': 'Doctor Reports'})
        report_types.append({'value': 'programme_summary', 'label': 'Programme Summary'})
        
        if 'FREE EYE CAMPS' in programme_name:
            # Check if the specific forms exist for this programme
            forms_response = supabase.table('forms').select('title').eq('project_id', project_id).execute()
            if forms_response.data:
                form_titles = [form['title'].upper() for form in forms_response.data]
                
                if any('READING GLASSES' in title for title in form_titles):
                    report_types.append({'value': 'reading_glasses', 'label': 'Reading Glasses Reports'})
                
                if any('EYE DROPS' in title for title in form_titles):
                    report_types.append({'value': 'eye_drops', 'label': 'Eye Drops Reports'})
        
        elif 'OBSTETRICS' in programme_name and 'GYNECOLOGY' in programme_name:
            # Check if pharmacy form exists  
            forms_response = supabase.table('forms').select('title').eq('project_id', project_id).execute()
            if forms_response.data:
                form_titles = [form['title'].upper() for form in forms_response.data]
                
                if any('PHARMACY' in title and 'GYNE' in title for title in form_titles):
                    report_types.append({'value': 'pharmacy_gyne', 'label': 'Pharmacy (Gyne) Reports'})
        
        return jsonify({'report_types': report_types})
        
    except Exception as e:
        print(f"Error getting report types: {str(e)}")
        return jsonify({'report_types': []})

@app.route('/api/doctors/<project_id>')
@login_required
def get_doctors_for_programme(project_id):
    """Get unique doctor names from a specific programme"""
    try:
        # Get all forms for this programme
        forms_query = supabase.table('forms').select('id').eq('project_id', project_id)
        forms_data = fetch_all_pages(forms_query, debug_name=f"doctors_project_{project_id}_forms")
        if not forms_data:
            return jsonify({'doctors': []})
        
        form_ids = [form['id'] for form in forms_data]
        
        # Get all submissions for these forms (with pagination)
        submissions_query = supabase.table('form_submissions').select('data').in_('form_id', form_ids)
        all_submissions = fetch_all_pages(submissions_query, debug_name="doctors_submissions")
        
        doctors = set()
        for submission in all_submissions:
            if submission.get('data'):
                # Look for doctor's name field (case insensitive)
                for key, value in submission['data'].items():
                    if key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor']:
                        if value and isinstance(value, str) and value.strip():
                            doctors.add(value.strip())
        
        # Also check patient records (with pagination)
        patients_query = supabase.table('patients').select('data')
        all_patients = fetch_all_pages(patients_query, debug_name="doctors_patients")
        for patient in all_patients:
            if patient.get('data'):
                for form_id, form_data in patient['data'].items():
                    if form_id in form_ids and isinstance(form_data, dict):
                        for key, value in form_data.items():
                            if key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor']:
                                if value and isinstance(value, str) and value.strip():
                                    doctors.add(value.strip())
        
        # Return sorted list of doctors with "ALL DOCTORS" option at the top
        doctor_list = sorted(list(doctors))
        if doctor_list:  # Only add ALL DOCTORS if there are actual doctors
            doctor_list.insert(0, "ALL DOCTORS")
        
        return jsonify({'doctors': doctor_list})
        
    except Exception as e:
        print(f"Error getting doctors: {str(e)}")
        return jsonify({'doctors': []}), 500

@app.route('/api/report_preview', methods=['POST'])
@login_required
def report_preview():
    """Get preview statistics for the report"""
    try:
        project_id = request.form.get('project_id')
        report_type = request.form.get('report_type')
        doctor_name = request.form.get('doctor')  # Only required for doctor reports
        date_type = request.form.get('dateType', 'today')
        
        if not project_id or not report_type:
            return jsonify({'totalPatients': 0})
        
        # For doctor reports, require doctor name
        if report_type == 'doctor' and not doctor_name:
            return jsonify({'totalPatients': 0})
        
        # Get date range
        if date_type == 'today':
            today = datetime.now(EAT).date()
            start_date = today
            end_date = today
        else:
            start_date = request.form.get('startDate')
            end_date = request.form.get('endDate')
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Get matching data based on report type
        if report_type == 'doctor':
            # For doctor reports, get patients as before
            data = get_patients_for_report(project_id, doctor_name, start_date, end_date)
            total_count = len(data)
        elif report_type == 'programme_summary':
            # For programme summary, get all patients
            data = get_patients_for_report(project_id, "ALL DOCTORS", start_date, end_date)
            total_count = len(data)
        else:
            # For form reports, get form submissions count
            data = get_form_submissions_for_report(project_id, report_type, start_date, end_date)
            total_count = len(data)
        
        return jsonify({
            'totalPatients': total_count,
            'programme': project_id,
            'report_type': report_type,
            'doctor': doctor_name if report_type == 'doctor' else None,
            'startDate': start_date.isoformat() if start_date else None,
            'endDate': end_date.isoformat() if end_date else None
        })
        
    except Exception as e:
        print(f"Error in report preview: {str(e)}")
        return jsonify({'totalPatients': 0}), 500

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    """Generate PDF report"""
    try:
        project_id = request.form.get('project_id')
        report_type = request.form.get('report_type')
        doctor_name = request.form.get('doctor')  # Only required for doctor reports
        date_type = request.form.get('dateType', 'today')
        
        if not project_id or not report_type:
            flash('Programme and report type are required', 'danger')
            return redirect(url_for('reports'))
        
        # For doctor reports, require doctor name
        if report_type == 'doctor' and not doctor_name:
            flash('Doctor name is required for doctor reports', 'danger')
            return redirect(url_for('reports'))
        
        # Get date range
        if date_type == 'today':
            today = datetime.now(EAT).date()
            start_date = today
            end_date = today
        else:
            start_date = request.form.get('startDate')
            end_date = request.form.get('endDate')
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Get programme name
        programme_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        programme_name = programme_response.data[0]['name'] if programme_response.data else 'Unknown Programme'
        
        # Generate PDF based on report type
        if report_type == 'doctor':
            # Generate doctor report (existing functionality)
            patients = get_patients_for_report(project_id, doctor_name, start_date, end_date)
            pdf_buffer = generate_pdf_report(patients, programme_name, doctor_name, start_date, end_date, project_id)
            
            # Create appropriate filename for ALL DOCTORS vs specific doctor
            if doctor_name == "ALL DOCTORS":
                filename = f"Medical_Report_ALL_DOCTORS_{programme_name}_{start_date}.pdf"
            else:
                filename = f"Medical_Report_{doctor_name}_{start_date}.pdf"
            
            log_activity('generate', 'report', project_id, f"Generated doctor report for {doctor_name} in {programme_name}")
            
        elif report_type == 'programme_summary':
            # Generate programme summary report (summary statistics only)
            patients = get_patients_for_report(project_id, "ALL DOCTORS", start_date, end_date)
            pdf_buffer = generate_programme_summary_pdf(patients, programme_name, start_date, end_date, project_id)
            
            filename = f"Programme_Summary_{programme_name.replace(' ', '_')}_{start_date}.pdf"
            log_activity('generate', 'report', project_id, f"Generated programme summary report for {programme_name}")
            
        else:
            # Generate form-specific report
            form_data = get_form_submissions_for_report(project_id, report_type, start_date, end_date)
            pdf_buffer = generate_form_report_pdf(form_data, programme_name, report_type, start_date, end_date, project_id)
            
            # Create filename for form reports
            report_type_names = {
                'reading_glasses': 'Reading_Glasses',
                'eye_drops': 'Eye_Drops', 
                'pharmacy_gyne': 'Pharmacy_Gyne'
            }
            report_name = report_type_names.get(report_type, report_type)
            filename = f"{report_name}_Report_{programme_name}_{start_date}.pdf"
            
            log_activity('generate', 'report', project_id, f"Generated {report_name} report in {programme_name}")
        
        # Return PDF as response
        from flask import make_response
        response = make_response(pdf_buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        flash('Error generating report. Please try again.', 'danger')
        return redirect(url_for('reports'))

def get_form_submissions_for_report(project_id, report_type, start_date, end_date):
    """Get form submissions for specific form types based on report type"""
    try:
        from datetime import timedelta
        
        # Map report types to form title patterns
        form_patterns = {
            'reading_glasses': ['READING GLASSES'],
            'eye_drops': ['EYE DROPS'],
            'pharmacy_gyne': ['PHARMACY', 'GYNE']
        }
        
        patterns = form_patterns.get(report_type, [])
        if not patterns:
            return []
        
        # Get forms that match the patterns for this project
        forms_query = supabase.table('forms').select('id, title').eq('project_id', project_id)
        forms_data = fetch_all_pages(forms_query, debug_name=f"form_report_project_{project_id}_forms")
        
        matching_form_ids = []
        for form in forms_data:
            form_title = form.get('title', '').upper()
            # Check if all patterns are in the form title
            if all(pattern in form_title for pattern in patterns):
                matching_form_ids.append(form['id'])
        
        if not matching_form_ids:
            return []
        
        # PERFORMANCE FIX: Get submissions for matching forms within date range - only fetch essential fields
        query = supabase.table('form_submissions').select('patient_id, data, created_at, form_id').in_('form_id', matching_form_ids)
        
        if start_date:
            query = query.gte('created_at', start_date.isoformat())
        if end_date:
            # Add one day to end_date to include all of that day
            end_date_plus_one = end_date + timedelta(days=1)
            query = query.lt('created_at', end_date_plus_one.isoformat())
        
        # PERFORMANCE FIX: Get all submissions with progress tracking
        submissions = fetch_all_pages(query, debug_name=f"form_report_{report_type}_submissions")
        
        # PERFORMANCE FIX: Add progress tracking for large datasets
        if len(submissions) > 500:
            print(f"Form Report: Processing {len(submissions)} submissions for {report_type} report...")
        
        return submissions
        
    except Exception as e:
        print(f"Error getting form submissions for report: {str(e)}")
        return []

def generate_form_report_pdf(form_data, programme_name, report_type, start_date, end_date, project_id):
    """Generate PDF report for form-specific data"""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from io import BytesIO
    
    # Create PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Get the default stylesheet
    styles = getSampleStyleSheet()
    
    # Create custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        alignment=1,  # Center
        textColor=colors.black,
        spaceAfter=30,
        fontName='Times-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        alignment=1,  # Center
        textColor=colors.black,
        spaceAfter=20,
        fontName='Times-Bold'
    )
    
    # Title based on report type
    report_titles = {
        'reading_glasses': 'READING GLASSES DISPENSED REPORT',
        'eye_drops': 'EYE DROPS & TABLETS DISPENSED REPORT',
        'pharmacy_gyne': 'PHARMACY (GYNE) DISPENSED REPORT'
    }
    
    title = report_titles.get(report_type, 'FORM REPORT')
    elements.append(Paragraph(title, title_style))
    elements.append(Paragraph(f"Programme: {programme_name}", subtitle_style))
    elements.append(Paragraph(f"Period: {start_date} to {end_date}", subtitle_style))
    elements.append(Spacer(1, 30))
    
    # Generate statistics based on report type
    if report_type == 'reading_glasses':
        stats_result = generate_reading_glasses_stats(form_data, styles)
    elif report_type == 'eye_drops':
        stats_result = generate_eye_drops_stats(form_data, styles)
    elif report_type == 'pharmacy_gyne':
        stats_result = generate_pharmacy_gyne_stats(form_data, styles)
    else:
        stats_result = None
    
    if stats_result:
        # Handle both single flowable objects and lists of flowable objects
        if isinstance(stats_result, list):
            elements.extend(stats_result)
        else:
            elements.append(stats_result)
    else:
        no_data = Paragraph("No data available for this report.", styles['Normal'])
        elements.append(no_data)
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_reading_glasses_stats(form_data, styles):
    """Generate reading glasses statistics table"""
    from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    
    # Count prescription strengths and unique patients
    prescription_counts = {}
    unique_patients = set()
    
    for submission in form_data:
        data = submission.get('data', {})
        patient_id = submission.get('patient_id')
        
        # Look for reading glasses field
        glasses_value = None
        for key, value in data.items():
            if 'reading glasses' in key.lower() and value:
                if str(value).strip().lower() not in ['not applicable', 'no', 'none', 'n/a', '']:
                    glasses_value = str(value).strip()
                    break
        
        if glasses_value:
            if glasses_value in prescription_counts:
                prescription_counts[glasses_value] += 1
            else:
                prescription_counts[glasses_value] = 1
            
            # Track unique patients
            if patient_id:
                unique_patients.add(patient_id)
    
    if not prescription_counts:
        return Paragraph("No reading glasses prescriptions found.", styles['Normal'])
    
    elements = []
    
    # Add patient count summary
    summary_style = ParagraphStyle(
        'SummaryStyle',
        parent=styles['Normal'],
        fontSize=14,
        fontName='Times-Bold',
        alignment=1,
        spaceAfter=20,
        textColor=colors.blue
    )
    
    elements.append(Paragraph(f"Total Patients Who Received Reading Glasses: {len(unique_patients)}", summary_style))
    elements.append(Spacer(1, 10))
    
    # Create table data
    header_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=12,
        fontName='Times-Bold',
        alignment=1,  # Center
        textColor=colors.white
    )
    
    data_style = ParagraphStyle(
        'DataCell',
        parent=styles['Normal'],
        fontSize=11,
        alignment=1,  # Center
        textColor=colors.black
    )
    
    # Sort prescriptions and create table data
    sorted_prescriptions = sorted(prescription_counts.items())
    
    table_data = [
        [Paragraph('Prescription Strength', header_style), Paragraph('Number Given', header_style)]
    ]
    
    total_given = 0
    for prescription, count in sorted_prescriptions:
        table_data.append([
            Paragraph(prescription, data_style),
            Paragraph(str(count), data_style)
        ])
        total_given += count
    
    # Add total row
    table_data.append([
        Paragraph('TOTAL', header_style),
        Paragraph(str(total_given), header_style)
    ])
    
    # Create table
    table = Table(table_data, colWidths=[3*inch, 2*inch])
    table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        
        # Data rows
        ('FONTNAME', (0, 1), (-1, -2), 'Times-Roman'),
        ('FONTSIZE', (0, 1), (-1, -2), 11),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.lightgrey]),
        
        # Total row
        ('BACKGROUND', (0, -1), (-1, -1), colors.grey),
        ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),
        ('FONTNAME', (0, -1), (-1, -1), 'Times-Bold'),
        ('FONTSIZE', (0, -1), (-1, -1), 12),
        
        # Borders
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
    ]))
    
    elements.append(table)
    return elements

def generate_eye_drops_stats(form_data, styles):
    """Generate eye drops statistics table"""
    from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    import json
    
    # Count dispensed items and unique patients
    eye_drops_counts = {}
    tablets_counts = {}
    patients_with_drops = set()
    patients_with_tablets = set()
    
    for submission in form_data:
        data = submission.get('data', {})
        patient_id = submission.get('patient_id')
        
        # Look for dispensed eye drops field
        for key, value in data.items():
            if 'dispensed eye drops' in key.lower() and value:
                # Handle list/array values
                drops_list = []
                if isinstance(value, list):
                    drops_list = value
                elif isinstance(value, str):
                    try:
                        drops_list = json.loads(value) if value.startswith('[') else [value]
                    except:
                        drops_list = [value]
                
                has_drops = False
                for drop in drops_list:
                    drop = str(drop).strip()
                    if drop and drop.lower() not in ['no', 'none', 'n/a', '']:
                        eye_drops_counts[drop] = eye_drops_counts.get(drop, 0) + 1
                        has_drops = True
                
                if has_drops and patient_id:
                    patients_with_drops.add(patient_id)
            
            # Look for dispensed tablets field
            elif 'dispensed tablets' in key.lower() and value:
                # Handle list/array values
                tablets_list = []
                if isinstance(value, list):
                    tablets_list = value
                elif isinstance(value, str):
                    try:
                        tablets_list = json.loads(value) if value.startswith('[') else [value]
                    except:
                        tablets_list = [value]
                
                has_tablets = False
                for tablet in tablets_list:
                    tablet = str(tablet).strip()
                    if tablet and tablet.lower() not in ['no', 'none', 'n/a', '']:
                        tablets_counts[tablet] = tablets_counts.get(tablet, 0) + 1
                        has_tablets = True
                
                if has_tablets and patient_id:
                    patients_with_tablets.add(patient_id)
    
    elements = []
    
    # Add patient count summary
    summary_style = ParagraphStyle(
        'SummaryStyle',
        parent=styles['Normal'],
        fontSize=14,
        fontName='Times-Bold',
        alignment=1,
        spaceAfter=20,
        textColor=colors.blue
    )
    
    total_patients = len(patients_with_drops | patients_with_tablets)
    elements.append(Paragraph(f"Total Patients Who Received Eye Drops or Tablets: {total_patients}", summary_style))
    if patients_with_drops:
        elements.append(Paragraph(f"Patients Who Received Eye Drops: {len(patients_with_drops)}", summary_style))
    if patients_with_tablets:
        elements.append(Paragraph(f"Patients Who Received Tablets: {len(patients_with_tablets)}", summary_style))
    elements.append(Spacer(1, 20))
    
    # Style definitions
    header_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=12,
        fontName='Times-Bold',
        alignment=1,
        textColor=colors.white
    )
    
    data_style = ParagraphStyle(
        'DataCell',
        parent=styles['Normal'],
        fontSize=11,
        alignment=1,
        textColor=colors.black
    )
    
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        fontName='Times-Bold',
        alignment=1,
        spaceAfter=10
    )
    
    # Eye Drops Table
    if eye_drops_counts:
        elements.append(Paragraph("EYE DROPS DISPENSED", section_style))
        
        table_data = [
            [Paragraph('Eye Drop', header_style), Paragraph('Number of Patients who received', header_style)]
        ]
        
        for drop, count in sorted(eye_drops_counts.items()):
            table_data.append([
                Paragraph(drop, data_style),
                Paragraph(str(count), data_style)
            ])
        
        table = Table(table_data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 30))
    
    # Tablets Table
    if tablets_counts:
        elements.append(Paragraph("TABLETS DISPENSED", section_style))
        
        table_data = [
            [Paragraph('Tablet', header_style), Paragraph('Number of Patients who received', header_style)]
        ]
        
        for tablet, count in sorted(tablets_counts.items()):
            table_data.append([
                Paragraph(tablet, data_style),
                Paragraph(str(count), data_style)
            ])
        
        table = Table(table_data, colWidths=[3*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
        ]))
        
        elements.append(table)
    
    if not eye_drops_counts and not tablets_counts:
        return Paragraph("No eye drops or tablets dispensed found.", styles['Normal'])
    
    return elements

def generate_pharmacy_gyne_stats(form_data, styles):
    """Generate pharmacy gyne statistics table"""
    from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    import json
    
    # Count dispensed medications and unique patients
    medication_counts = {}
    unique_patients = set()
    
    for submission in form_data:
        data = submission.get('data', {})
        patient_id = submission.get('patient_id')
        
        # Look for dispensed medication field
        for key, value in data.items():
            if 'dispenseed medication' in key.lower() and value:  # Note: typo in field name as per your data
                # Handle list/array values
                medications_list = []
                if isinstance(value, list):
                    medications_list = value
                elif isinstance(value, str):
                    try:
                        medications_list = json.loads(value) if value.startswith('[') else [value]
                    except:
                        medications_list = [value]
                
                has_medication = False
                for medication in medications_list:
                    medication = str(medication).strip()
                    if medication and medication.lower() not in ['no', 'none', 'n/a', '']:
                        medication_counts[medication] = medication_counts.get(medication, 0) + 1
                        has_medication = True
                
                if has_medication and patient_id:
                    unique_patients.add(patient_id)
    
    if not medication_counts:
        return Paragraph("No medications dispensed found.", styles['Normal'])
    
    elements = []
    
    # Add patient count summary
    summary_style = ParagraphStyle(
        'SummaryStyle',
        parent=styles['Normal'],
        fontSize=14,
        fontName='Times-Bold',
        alignment=1,
        spaceAfter=20,
        textColor=colors.blue
    )
    
    elements.append(Paragraph(f"Total Patients Who Received Medications: {len(unique_patients)}", summary_style))
    elements.append(Spacer(1, 10))
    
    # Create table data
    header_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=12,
        fontName='Times-Bold',
        alignment=1,
        textColor=colors.white
    )
    
    data_style = ParagraphStyle(
        'DataCell',
        parent=styles['Normal'],
        fontSize=11,
        alignment=1,
        textColor=colors.black
    )
    
    # Sort medications and create table data
    sorted_medications = sorted(medication_counts.items())
    
    table_data = [
        [Paragraph('Medication', header_style), Paragraph('Number of Patients who received', header_style)]
    ]
    
    for medication, count in sorted_medications:
        table_data.append([
            Paragraph(medication, data_style),
            Paragraph(str(count), data_style)
        ])
    
    # Create table
    table = Table(table_data, colWidths=[4*inch, 2*inch])
    table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        
        # Data rows
        ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        
        # Borders
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
    ]))
    
    elements.append(table)
    return elements

def get_patients_for_report(project_id, doctor_name, start_date, end_date):
    """Get patients data for the report based on filters"""
    try:
        from datetime import timedelta
        
        # Get all forms for this programme
        forms_query = supabase.table('forms').select('id').eq('project_id', project_id)
        forms_data = fetch_all_pages(forms_query, debug_name=f"report_project_{project_id}_forms")
        if not forms_data:
            return []
        
        form_ids = [form['id'] for form in forms_data]
        
        # Get all submissions for these forms within date range
        # PERFORMANCE FIX: Only fetch essential fields to reduce memory usage and network transfer
        query = supabase.table('form_submissions').select('patient_id, data, created_at, form_id').in_('form_id', form_ids)
        
        if start_date:
            query = query.gte('created_at', start_date.isoformat())
        if end_date:
            # Add one day to end_date to include all of that day
            end_date_plus_one = end_date + timedelta(days=1)
            query = query.lt('created_at', end_date_plus_one.isoformat())
        
        # PERFORMANCE FIX: For specific doctors (not ALL DOCTORS), add database-level filtering if possible
        if doctor_name != "ALL DOCTORS":
            # Note: We can't easily filter by doctor at DB level due to JSON field variations
            # So we'll fetch all and filter in memory (still faster than before due to other optimizations)
            pass
        
        # Use pagination to fetch ALL submissions
        print(f"Report: Query being executed - Forms: {form_ids}, Date range: {start_date} to {end_date}")
        all_submissions = fetch_all_pages(query, debug_name="report_submissions", page_size=1000)
        print(f"Report: CRITICAL DEBUG - Total submissions fetched: {len(all_submissions)}")
        
        # PERFORMANCE FIX: Process submissions more efficiently with early filtering
        all_patient_data = {}
        patients_with_doctor = set()
        
        # Track processing progress for large datasets
        total_submissions = len(all_submissions)
        if total_submissions > 1000:
            print(f"Report: Processing {total_submissions} submissions for report generation...")
        
        for idx, submission in enumerate(all_submissions):
            # Progress tracking for large datasets
            if total_submissions > 1000 and idx % 1000 == 0:
                print(f"Report: Processed {idx}/{total_submissions} submissions ({(idx/total_submissions)*100:.1f}%)")
                
            # PERFORMANCE FIX: Skip submissions with no data early to avoid unnecessary processing
            if not submission.get('data') or not submission.get('patient_id'):
                continue
            
            patient_id = submission['patient_id']
            
            # Aggregate all data for this patient
            if patient_id not in all_patient_data:
                all_patient_data[patient_id] = {
                    'patient_id': patient_id,
                    'data': {},
                    'latest_date': submission.get('created_at')
                }
            
            # Merge submission data from ALL forms
            all_patient_data[patient_id]['data'].update(submission['data'])
            
            # Keep track of latest submission date
            if submission.get('created_at') > all_patient_data[patient_id]['latest_date']:
                all_patient_data[patient_id]['latest_date'] = submission.get('created_at')
            
            # Handle ALL DOCTORS case or specific doctor
            if doctor_name == "ALL DOCTORS":
                # For ALL DOCTORS, include ALL patients - we'll check for essential data after merging centralized registration
                # This fixes the issue where patients with complete registration data but minimal form data were excluded
                patients_with_doctor.add(patient_id)
# Removed verbose logging for better performance
            else:
                # Check if this submission has the specified doctor
                for key, value in submission['data'].items():
                    if (key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor'] 
                        and value and str(value).strip().lower() == doctor_name.lower()):
                        patients_with_doctor.add(patient_id)
# Removed verbose logging for better performance
                        break
        
        # Now fetch centralized registration data for all patients and merge it
        patient_ids = list(all_patient_data.keys())
        print(f"Report: Fetching centralized registration data for {len(patient_ids)} patients")
        
        # PERFORMANCE FIX: Skip registration data fetch if no patients
        if not patient_ids:
            print("Report: No patients found, skipping registration data fetch")
            return []
        
        # CRITICAL FIX: Use chunked batch processing to avoid Supabase query limits
        if patient_ids:
            try:
                registration_lookup = {}
                chunk_size = 100  # Smaller chunks to avoid Supabase limits
                total_chunks = (len(patient_ids) + chunk_size - 1) // chunk_size
                
                print(f"Report: Fetching registration data in {total_chunks} chunks for {len(patient_ids)} patients")
                
                for i in range(0, len(patient_ids), chunk_size):
                    chunk = patient_ids[i:i + chunk_size]
                    chunk_num = (i // chunk_size) + 1
                    
                    try:
                        batch_response = supabase.table('patients')\
                            .select('patient_id, data, created_at')\
                            .in_('patient_id', chunk)\
                            .execute()
                        
                        chunk_count = 0
                        for patient_record in batch_response.data:
                            patient_id = patient_record.get('patient_id')
                            if patient_id and patient_record.get('data', {}).get('registration'):
                                registration_lookup[patient_id] = {
                                    'registration': patient_record['data']['registration'],
                                    'created_at': patient_record.get('created_at', '')
                                }
                                chunk_count += 1
                        
                        print(f"Report: Chunk {chunk_num}/{total_chunks}: {chunk_count} registration records found")
                        
                    except Exception as chunk_error:
                        print(f"Report: Error fetching chunk {chunk_num}: {str(chunk_error)}")
                        continue
                
                print(f"Report: TOTAL registration data fetched: {len(registration_lookup)} patients")
                
                # Now merge registration data with form data (much faster)
                for patient_id, patient_info in all_patient_data.items():
                    if patient_id in registration_lookup:
                        registration_data = registration_lookup[patient_id]['registration']
                        
                        # Merge registration data with form data (registration data takes priority)
                        merged_data = {}
                        merged_data.update(patient_info['data'])  # Form data first
                        merged_data.update(registration_data)     # Registration data overwrites/adds
                        
                        patient_info['data'] = merged_data
                    
            except Exception as e:
                print(f"Report: Error batch fetching registration data: {str(e)}")
                print("Report: Continuing without registration data to avoid delays")
        
        # PERFORMANCE FIX: More efficient filtering using list comprehension
        # CRITICAL FIX: Remove essential data filtering for ALL DOCTORS - everyone should have registration data
        # The issue was that patients with complete registration data but minimal form data were being excluded
        filtered_patient_data = [
            patient_info for patient_id, patient_info in all_patient_data.items() 
            if patient_id in patients_with_doctor
        ]
        
        print(f"Report: Returning {len(filtered_patient_data)} patients for report generation")
        return filtered_patient_data
        
    except Exception as e:
        print(f"Error getting patients for report: {str(e)}")
        return []

def get_field_value(patient_data, field_names):
    """
    Helper function to get field value from patient data using multiple possible field name variants.
    Returns the first matching field value found, or empty string if none found.
    """
    if not patient_data or not field_names:
        return ''
    
    for field_name in field_names:
        # Try exact match first
        if field_name in patient_data:
            value = patient_data[field_name]
            if value is not None and str(value).strip():
                return str(value).strip()
        
        # Try case-insensitive match
        for key, value in patient_data.items():
            if key.lower().strip().replace(' ', '').replace('_', '') == field_name.lower().strip().replace(' ', '').replace('_', ''):
                if value is not None and str(value).strip():
                    return str(value).strip()
    
    return ''

def build_treatment_plan(patient_data, programme_name=None):
    """
    Build treatment plan based on programme type
    """
    if not patient_data:
        return ''

    # Check if this is FREE EYE CAMPS programme
    if programme_name and 'FREE EYE CAMPS' in programme_name.upper():
        return build_eye_camp_treatment_plan(patient_data)
    # Check if this is OBSTETRICS & GYNECOLOGY programme
    elif programme_name and 'OBSTETRICS' in programme_name.upper() and 'GYNECOLOGY' in programme_name.upper():
        return build_gyne_treatment_plan(patient_data)
    else:
        # Generic treatment plan for other programmes
        return build_generic_treatment_plan(patient_data)

def build_eye_camp_treatment_plan(patient_data):
    """
    Build treatment plan for FREE EYE CAMPS with priority: Surgical Procedure > Eyedrops & Tabs > Reading Glasses
    """
    def clean_field_value(value):
        """Clean and extract actual values from field data, handling lists properly"""
        if not value:
            return ''
        
        # Handle list values (from checkboxes/multi-select)
        if isinstance(value, list):
            valid_items = []
            for item in value:
                if item and str(item).strip().lower() not in ['no', 'none', 'n/a', '']:
                    valid_items.append(str(item).strip())
            return ' + '.join(valid_items) if valid_items else ''
        
        # Handle single values
        value_str = str(value).strip()
        if value_str.startswith('[') and value_str.endswith(']'):
            # Handle string representation of lists like "['SICS', 'EXCISION']"
            try:
                import ast
                parsed_list = ast.literal_eval(value_str)
                if isinstance(parsed_list, list):
                    valid_items = []
                    for item in parsed_list:
                        if item and str(item).strip().lower() not in ['no', 'none', 'n/a', '']:
                            valid_items.append(str(item).strip())
                    return ' + '.join(valid_items) if valid_items else ''
            except:
                pass
        
        # Regular single value
        if value_str.lower() not in ['no', 'none', 'n/a', '']:
            return value_str
        return ''
    
    treatment_parts = []
    
    # Priority 1: Surgical Procedure
    surgical_procedure = get_field_value(patient_data, [
        'Surgical Procedure', 'surgical procedure', 'surgery', 'procedure',
        'Treatment Plan (Surgical Procedure)', 'treatment plan (surgical procedure)',
        'Surgery', 'Procedure', 'SURGICAL PROCEDURE', 'SURGERY'
    ])
    cleaned_surgery = clean_field_value(surgical_procedure)
    if cleaned_surgery:
        treatment_parts.append(cleaned_surgery.upper())
    
    # Priority 2: Eyedrops & Tabs
    eyedrops = get_field_value(patient_data, [
        'Eyedrops & Tabs', 'eyedrops & tabs', 'eyedrops and tabs', 'medications',
        'Treatment Plan (Eyedrops & Tabs)', 'treatment plan (eyedrops & tabs)',
        'Eyedrops', 'eyedrops', 'drops', 'Drops', 'EYEDROPS', 'medicine', 'Medicine'
    ])
    cleaned_eyedrops = clean_field_value(eyedrops)
    if cleaned_eyedrops:
        treatment_parts.append(cleaned_eyedrops.upper())
    
    # Priority 3: Reading Glasses
    reading_glasses = get_field_value(patient_data, [
        'Reading Glasses', 'reading glasses', 'glasses', 'Glasses',
        'Treatment Plan (Eye Glasses)', 'treatment plan (eye glasses)',
        'READING GLASSES', 'GLASSES', 'spectacles', 'Spectacles'
    ])
    cleaned_glasses = clean_field_value(reading_glasses)
    if cleaned_glasses:
        treatment_parts.append('READING GLASS')
    
    # Join all treatment parts
    return ' + '.join(treatment_parts) if treatment_parts else ''

def build_generic_treatment_plan(patient_data):
    """
    Build generic treatment plan for any programme - looks for common treatment-related fields
    """
    treatment_parts = []
    
    # Common treatment field patterns to look for
    treatment_field_patterns = [
        'treatment', 'therapy', 'medication', 'prescription', 'plan', 'intervention',
        'procedure', 'surgery', 'referral', 'recommendation', 'management'
    ]
    
    # Scan through all patient data to find treatment-related fields
    for key, value in patient_data.items():
        if value and str(value).strip() and str(value).lower().strip() not in ['no', 'none', 'n/a', '']:
            key_lower = key.lower()
            
            # Special handling for eye glasses fields to match eye camp format
            if ('treatment plan' in key_lower and 'eye glasses' in key_lower) or \
               ('reading glasses' in key_lower) or \
               ('glasses' in key_lower and 'treatment' in key_lower):
                # Convert eye glasses references to standard format for statistics counting
                treatment_parts.append('READING GLASS')
                continue
            
            # Check if this field contains any treatment-related keywords
            if any(pattern in key_lower for pattern in treatment_field_patterns):
                # Clean up the value and add it
                clean_value = str(value).strip().upper()
                if clean_value not in treatment_parts:
                    treatment_parts.append(clean_value)
    
    # Join all treatment parts
    return ' + '.join(treatment_parts) if treatment_parts else ''

def build_gyne_treatment_plan(patient_data):
    """
    Build treatment plan for OBSTETRICS & GYNECOLOGY - specific field prioritization
    """
    def clean_field_value(value):
        """Clean and extract actual values from field data, handling lists properly"""
        if not value:
            return ''
        
        # Handle list values (from checkboxes/multi-select)
        if isinstance(value, list):
            valid_items = []
            for item in value:
                if item and str(item).strip().lower() not in ['no', 'none', 'n/a', '']:
                    valid_items.append(str(item).strip())
            return ' + '.join(valid_items) if valid_items else ''
        
        # Handle single values
        value_str = str(value).strip()
        if value_str.startswith('[') and value_str.endswith(']'):
            # Handle string representation of lists like "['SURGERY', 'CRYOTHERAPY']"
            try:
                import ast
                parsed_list = ast.literal_eval(value_str)
                if isinstance(parsed_list, list):
                    valid_items = []
                    for item in parsed_list:
                        if item and str(item).strip().lower() not in ['no', 'none', 'n/a', '']:
                            valid_items.append(str(item).strip())
                    return ' + '.join(valid_items) if valid_items else ''
            except:
                pass
        
        # Regular single value
        if value_str.lower() not in ['no', 'none', 'n/a', '']:
            return value_str
        return ''
    
    treatment_parts = []
    
    # Priority 1: Medication from exact field
    medication = get_field_value(patient_data, ['Medication'])
    cleaned_medication = clean_field_value(medication)
    if cleaned_medication:
        treatment_parts.append(cleaned_medication.upper())
    
    # Priority 2: Surgical Procedure from exact field
    surgical_procedure = get_field_value(patient_data, ['Surgical Procedure'])
    cleaned_surgery = clean_field_value(surgical_procedure)
    if cleaned_surgery:
        treatment_parts.append(cleaned_surgery.upper())
    
    # Priority 3: Other treatments from Treatment Plan field (Counselling, Referral, Cryotherapy)
    treatment_plan = get_field_value(patient_data, ['Treatment Plan'])
    
    if treatment_plan:
        plan_list = treatment_plan if isinstance(treatment_plan, list) else [treatment_plan]
        for plan_item in plan_list:
            plan_item_str = str(plan_item).strip()
            if plan_item_str in ['Counselling', 'Referral', 'Cryotherapy']:
                treatment_parts.append(plan_item_str.upper())
    
    # Join all treatment parts
    return ' + '.join(treatment_parts) if treatment_parts else ''

def generate_pdf_report(patients, programme_name, doctor_name, start_date, end_date, project_id):
    """Generate PDF report using reportlab"""
    from reportlab.lib.pagesizes import letter, A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageTemplate, Frame, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from io import BytesIO
    import datetime
    import os
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=36, leftMargin=36, topMargin=50, bottomMargin=18)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Check if we need to generate individual reports for all doctors
    if doctor_name == "ALL DOCTORS":
        # PERFORMANCE FIX: Fetch ALL patient data once, then filter by doctor in memory
        all_patients_data = get_patients_for_report(project_id, "ALL DOCTORS", start_date, end_date)
        
        if not all_patients_data:
            # If no patients found, create empty report
            elements = create_empty_report_elements(programme_name, doctor_name, start_date, end_date)
        else:
            # Extract unique doctors from the patient data (much faster than separate DB query)
            all_doctors = get_unique_doctors_from_patients(all_patients_data)
        
        if not all_doctors:
            # If no doctors found in patient data, create empty report
            elements = create_empty_report_elements(programme_name, doctor_name, start_date, end_date)
        else:
            # Generate individual report for each doctor using pre-fetched data
            for i, individual_doctor in enumerate(all_doctors):
                # Filter patients for this specific doctor from the already-fetched data
                doctor_patients = filter_patients_by_doctor(all_patients_data, individual_doctor)
                
                # Add page break before each doctor's report (except the first one)
                if i > 0:
                    elements.append(PageBreak())
                
                # Generate individual doctor report elements based on programme type
                if 'OBSTETRICS' in programme_name.upper() and 'GYNECOLOGY' in programme_name.upper():
                    doctor_elements = create_gyne_doctor_report_elements(
                        doctor_patients, programme_name, individual_doctor, start_date, end_date, project_id
                    )
                else:
                    doctor_elements = create_individual_doctor_report_elements(
                        doctor_patients, programme_name, individual_doctor, start_date, end_date, project_id
                    )
                
                elements.extend(doctor_elements)
        
        # Build PDF and return
        doc.build(elements)
        buffer.seek(0)
        return buffer
    
    # Original single doctor report logic below
    # Single doctor report dispatch based on programme type
    if 'OBSTETRICS' in programme_name.upper() and 'GYNECOLOGY' in programme_name.upper():
        elements = create_gyne_doctor_report_elements(
            patients, programme_name, doctor_name, start_date, end_date, project_id
        )
    else:
        elements = create_individual_doctor_report_elements(
            patients, programme_name, doctor_name, start_date, end_date, project_id
        )
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

def get_unique_doctors_from_patients(patients_data):
    """Extract unique doctors from already-fetched patient data (much faster than DB query)"""
    doctors = set()
    
    for patient in patients_data:
        patient_data = patient.get('data', {})
        
        # Look for doctor name in various possible field names
        for key, value in patient_data.items():
            if (key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor'] 
                and value and str(value).strip()):
                doctors.add(str(value).strip())
                break
    
    return sorted(list(doctors))

def filter_patients_by_doctor(patients_data, doctor_name):
    """Filter patients for a specific doctor from already-fetched data"""
    filtered_patients = []
    
    for patient in patients_data:
        patient_data = patient.get('data', {})
        
        # Check if this patient was seen by the specified doctor
        for key, value in patient_data.items():
            if (key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor'] 
                and value and str(value).strip().lower() == doctor_name.lower()):
                filtered_patients.append(patient)
                break
    
    return filtered_patients

def get_unique_doctors_for_project(project_id, start_date, end_date):
    """Get all unique doctors for a specific project and date range (legacy function - kept for compatibility)"""
    try:
        from datetime import timedelta
        
        # Get all forms for this programme
        forms_query = supabase.table('forms').select('id').eq('project_id', project_id)
        forms_data = fetch_all_pages(forms_query, debug_name=f"unique_doctors_project_{project_id}_forms")
        if not forms_data:
            return []
        
        form_ids = [form['id'] for form in forms_data]
        
        # Get all submissions for these forms within date range
        query = supabase.table('form_submissions').select('data').in_('form_id', form_ids)
        
        if start_date:
            query = query.gte('created_at', start_date.isoformat())
        if end_date:
            # Add one day to end_date to include all of that day
            end_date_plus_one = end_date + timedelta(days=1)
            query = query.lt('created_at', end_date_plus_one.isoformat())
        
        # Use pagination to fetch ALL submissions
        all_submissions = fetch_all_pages(query, debug_name="unique_doctors_submissions")
        
        doctors = set()
        for submission in all_submissions:
            if submission.get('data'):
                # Look for doctor's name field (case insensitive)
                for key, value in submission['data'].items():
                    if key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor']:
                        if value and isinstance(value, str) and value.strip():
                            doctors.add(value.strip())
        
        # Also check patient records (with pagination)
        patients_query = supabase.table('patients').select('data')
        all_patients = fetch_all_pages(patients_query, debug_name="unique_doctors_patients")
        for patient in all_patients:
            if patient.get('data'):
                for form_id, form_data in patient['data'].items():
                    if form_id in form_ids and isinstance(form_data, dict):
                        for key, value in form_data.items():
                            if key.lower().replace(' ', '').replace("'", '') in ['doctorsname', 'doctorname', 'doctor']:
                                if value and isinstance(value, str) and value.strip():
                                    doctors.add(value.strip())
        
        # Return sorted list of doctors
        return sorted(list(doctors))
        
    except Exception as e:
        print(f"Error getting unique doctors: {str(e)}")
        return []

def create_empty_report_elements(programme_name, doctor_name, start_date, end_date):
    """Create elements for empty report when no doctors found"""
    from reportlab.platypus import Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    import os
    
    elements = []
    
    # Add MDF logo
    logo_path = os.path.join(os.path.dirname(__file__), 'MDF.png')
    if os.path.exists(logo_path):
        try:
            logo = Image(logo_path, width=1.0*inch, height=0.8*inch, kind='proportional')
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 15))
        except Exception as e:
            print(f"Could not load logo: {str(e)}")
    
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'ReportTitle', 
        parent=styles['Heading1'], 
        fontSize=18, 
        alignment=1,
        textColor=colors.black,
        fontName='Times-Bold',
        spaceAfter=20
    )
    
    title = Paragraph(f"MEDICAL CAMP REPORT<br/><font size='14'>{programme_name}</font>", title_style)
    elements.append(title)
    
    # No data message
    no_data_style = ParagraphStyle(
        'NoData', 
        parent=styles['Normal'], 
        fontSize=12, 
        alignment=1,
        textColor=colors.black,
        fontName='Times-Italic',
        spaceAfter=20
    )
    no_data = Paragraph("No doctors found for the selected criteria.", no_data_style)
    elements.append(no_data)
    
    return elements

def create_individual_doctor_report_elements(patients, programme_name, doctor_name, start_date, end_date, project_id):
    """Create report elements for an individual doctor (similar to original single doctor report)"""
    from reportlab.platypus import Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    import datetime
    import os
    
    elements = []
    
    # Add MDF logo for each doctor's report
    logo_path = os.path.join(os.path.dirname(__file__), 'MDF.png')
    if os.path.exists(logo_path):
        try:
            logo = Image(logo_path, width=1.0*inch, height=0.8*inch, kind='proportional')
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 15))
        except Exception as e:
            print(f"Could not load logo: {str(e)}")
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Title styling
    title_style = ParagraphStyle(
        'ReportTitle', 
        parent=styles['Heading1'], 
        fontSize=18, 
        alignment=1,
        textColor=colors.black,
        fontName='Times-Bold',
        spaceAfter=20
    )
    
    # Main title
    title = Paragraph(f"MEDICAL CAMP REPORT<br/><font size='14'>{programme_name}</font>", title_style)
    elements.append(title)
    
    # Report details
    if start_date == end_date:
        date_str = start_date.strftime('%B %d, %Y')
    else:
        date_str = f"{start_date.strftime('%B %d, %Y')} - {end_date.strftime('%B %d, %Y')}"
    
    # Create header info table
    generated_at = datetime.datetime.now(EAT).strftime('%B %d, %Y at %I:%M %p EAT')
    header_data = [
        ['Doctor:', doctor_name],
        ['Date:', date_str],
        ['Total Patients:', str(len(patients))],
        ['Generated:', generated_at]
    ]
    
    header_table = Table(header_data, colWidths=[2*inch, 4*inch])
    header_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Times-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Times-Roman'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(header_table)
    elements.append(Spacer(1, 30))
    
    if not patients:
        no_data_style = ParagraphStyle(
            'NoData', 
            parent=styles['Normal'], 
            fontSize=12, 
            alignment=1,
            textColor=colors.black,
            fontName='Times-Italic',
            spaceAfter=20
        )
        no_data = Paragraph("No patients found for this doctor.", no_data_style)
        elements.append(no_data)
    else:
        # Create table headers based on programme type (same as original)
        if 'FREE EYE CAMPS' in programme_name.upper():
            headers = ['Patient ID', 'Name', 'Gender', 'Age', 'VA RE', 'VA LE', 'Diagnosis', 'Treatment Plan', 'Address', 'Phone']
        else:
            headers = ['Patient ID', 'Name', 'Gender', 'Age', 'Diagnosis', 'Treatment Plan', 'Address', 'Phone']
        data = [headers]
        
        for patient in patients:
            patient_data = patient.get('data', {})
            
            # Extract required fields with various possible field names
            patient_id = patient.get('patient_id', '')
            name = get_field_value(patient_data, [
                'Name', 'name', 'patient name', 'full name', 'patient_name', 'full_name', 
                'Patient Name', 'Full Name', 'NAME'
            ])
            gender = get_field_value(patient_data, [
                'Gender', 'gender', 'sex', 'Sex', 'GENDER', 'SEX'
            ])
            age = get_field_value(patient_data, [
                'Age (Years)', 'age (years)', 'age', 'age years', 'Age', 'AGE', 
                'age_years', 'Age Years', 'age(years)', 'Age(Years)'
            ])
            
            # Extract eye-specific fields only for FREE EYE CAMPS
            if 'FREE EYE CAMPS' in programme_name.upper():
                va_re = get_field_value(patient_data, [
                    'va re', 'visual acuity re', 'right eye', 'va right', 'VA RE', 'Visual Acuity RE',
                    'va_re', 'visual_acuity_re', 'Right Eye', 'VA Right'
                ])
                va_le = get_field_value(patient_data, [
                    'va le', 'visual acuity le', 'left eye', 'va left', 'VA LE', 'Visual Acuity LE',
                    'va_le', 'visual_acuity_le', 'Left Eye', 'VA Left'
                ])
            else:
                va_re = ''
                va_le = ''
                
            diagnosis = get_field_value(patient_data, [
                'diagnosis', 'diagnoses', 'Diagnosis', 'Diagnoses', 'DIAGNOSIS', 
                'Diagnose', 'diagnose'
            ])
            
            # Build treatment plan
            treatment_plan = build_treatment_plan(patient_data, programme_name)
            
            # Physical address
            address = get_field_value(patient_data, [
                'Ward', 'ward', 'physical address', 'address', 'Address', 'WARD', 
                'Physical Address', 'PHYSICAL ADDRESS'
            ])
            
            # Phone number
            phone = get_field_value(patient_data, [
                'Phone Number', 'phone number', 'phone', 'Phone', 'PHONE NUMBER', 
                'PHONE', 'mobile', 'Mobile', 'contact number', 'Contact Number'
            ])
            
            # Build row based on programme type
            if 'FREE EYE CAMPS' in programme_name.upper():
                row = [
                    patient_id,
                    name or '',
                    gender or '',
                    age or '',
                    va_re or '',
                    va_le or '',
                    diagnosis or '',
                    treatment_plan or '',
                    address or '',
                    phone or ''
                ]
            else:
                row = [
                    patient_id,
                    name or '',
                    gender or '',
                    age or '',
                    diagnosis or '',
                    treatment_plan or '',
                    address or '',
                    phone or ''
                ]
            data.append(row)
        
        # Create table with optimized column widths based on programme type
        if 'FREE EYE CAMPS' in programme_name.upper():
            col_widths = [
                0.9 * inch,  # Patient ID
                1.3 * inch,  # Name
                0.6 * inch,  # Gender
                0.6 * inch,  # Age
                0.7 * inch,  # VA RE
                0.7 * inch,  # VA LE
                1.4 * inch,  # Diagnosis
                1.5 * inch,  # Treatment Plan
                1.0 * inch,  # Address
                1.0 * inch,  # Phone
            ]
        else:
            col_widths = [
                1.0 * inch,  # Patient ID
                1.8 * inch,  # Name
                0.8 * inch,  # Gender
                0.8 * inch,  # Age
                2.0 * inch,  # Diagnosis
                2.2 * inch,  # Treatment Plan
                1.2 * inch,  # Address
                1.2 * inch,  # Phone
            ]
        
        # Add table title
        table_title_style = ParagraphStyle(
            'TableTitle',
            parent=styles['Heading2'],
            fontSize=14,
            alignment=1,
            textColor=colors.black,
            fontName='Times-Bold',
            spaceAfter=15
        )
        table_title = Paragraph("PATIENT DATA", table_title_style)
        elements.append(table_title)
        
        # Process data for proper text wrapping
        processed_data = []
        for i, row in enumerate(data):
            if i == 0:  # Header row
                processed_data.append(row)
            else:
                processed_row = []
                for j, cell in enumerate(row):
                    if j in [1, 6, 7, 8, 9]:  # Name, Diagnosis, Treatment, Address, Phone columns
                        if cell and len(str(cell)) > 15:
                            # Create paragraph for long text
                            cell_style = ParagraphStyle(
                                'CellText',
                                parent=styles['Normal'],
                                fontName='Times-Roman',
                                fontSize=8,
                                leading=10
                            )
                            processed_row.append(Paragraph(str(cell), cell_style))
                        else:
                            processed_row.append(cell or '')
                    else:
                        processed_row.append(cell or '')
                processed_data.append(processed_row)
        
        table = Table(processed_data, repeatRows=1, colWidths=col_widths)
        table.setStyle(TableStyle([
            # Header styling
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            
            # Data rows styling
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            
            # Alignment
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Patient ID centered
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # Name left-aligned
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),  # Gender centered
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),  # Age centered
            ('ALIGN', (4, 1), (5, -1), 'CENTER'),  # VA fields centered
            ('ALIGN', (6, 1), (6, -1), 'LEFT'),    # Diagnosis left-aligned
            ('ALIGN', (7, 1), (7, -1), 'LEFT'),    # Treatment left-aligned
            ('ALIGN', (8, 1), (8, -1), 'LEFT'),    # Address left-aligned
            ('ALIGN', (9, 1), (9, -1), 'LEFT'),    # Phone left-aligned
            
            # Vertical alignment
            ('VALIGN', (0, 1), (-1, -1), 'TOP'),
            
            # Padding
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('LEFTPADDING', (0, 1), (-1, -1), 6),
            ('RIGHTPADDING', (0, 1), (-1, -1), 6),
            
            # Grid and borders
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
        ]))
        
        elements.append(table)
        
        # Add summary statistics
        add_summary_statistics(elements, patients, styles, project_id, start_date, end_date, programme_name)
    
    return elements

def create_gyne_doctor_report_elements(patients, programme_name, doctor_name, start_date, end_date, project_id):
    """Create GYNE-specific report elements with specialized table structure"""
    from reportlab.platypus import Paragraph, Spacer, Image, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    import datetime
    import os
    
    elements = []
    
    # Add MDF logo
    logo_path = os.path.join(os.path.dirname(__file__), 'MDF.png')
    if os.path.exists(logo_path):
        try:
            logo = Image(logo_path, width=1.0*inch, height=0.8*inch, kind='proportional')
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 15))
        except Exception as e:
            print(f"Could not load logo: {str(e)}")
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Title styling
    title_style = ParagraphStyle(
        'ReportTitle', 
        parent=styles['Heading1'], 
        fontSize=18, 
        alignment=1,
        textColor=colors.black,
        fontName='Times-Bold',
        spaceAfter=20
    )
    
    # Main title
    title = Paragraph(f"GYNE PATIENTS SUMMARY REPORT<br/><font size='14'>{programme_name}</font>", title_style)
    elements.append(title)
    
    # Report details
    if start_date == end_date:
        date_str = start_date.strftime('%B %d, %Y')
    else:
        date_str = f"{start_date.strftime('%B %d, %Y')} - {end_date.strftime('%B %d, %Y')}"
    
    # Create header info table
    generated_at = datetime.datetime.now(EAT).strftime('%B %d, %Y at %I:%M %p EAT')
    header_data = [
        ['Doctor:', doctor_name],
        ['Date:', date_str],
        ['Total Patients:', str(len(patients))],
        ['Generated:', generated_at]
    ]
    
    header_table = Table(header_data, colWidths=[2*inch, 4*inch])
    header_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Times-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Times-Roman'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(header_table)
    elements.append(Spacer(1, 30))
    
    if not patients:
        no_data_style = ParagraphStyle(
            'NoData', 
            parent=styles['Normal'], 
            fontSize=12, 
            alignment=1,
            textColor=colors.black,
            fontName='Times-Italic',
            spaceAfter=20
        )
        no_data = Paragraph("No patients found for this doctor.", no_data_style)
        elements.append(no_data)
    else:
        # GYNE-specific table headers
        headers = [
            'Name', 'Age', 'Suspect for\nCervical CA', 'VIA\nNEG', 'VIA Small\nLesion', 
            'VIA Large\nLesion', 'Breast\nExamination', 'Surgeries', 
            'Diagnosis', 'Plan', 'Contact', 'Address'
        ]
        data = [headers]
        
        for patient in patients:
            patient_data = patient.get('data', {})
            
            # Extract required fields using exact form field names
            name = get_field_value(patient_data, ['Name'])
            age = get_field_value(patient_data, ['Age (Years)'])
            
            # CX Visual Inspection (Suspect for CA) - based on "Abnormal Visual Inspection"
            abnormal_visual = get_field_value(patient_data, ['Abnormal Visual Inspection'])
            cx_visual = 'Yes' if abnormal_visual and 'Suspect for Cervical Cancer' in str(abnormal_visual) else 'No'
            
            # VIA Test results
            via_inspection = get_field_value(patient_data, ['VIA Inspection'])
            if not via_inspection or str(via_inspection).strip() == '':
                via_neg = 'Not Done'
            elif via_inspection == 'Negative':
                via_neg = 'Yes'
            else:
                via_neg = 'No'
            
            # VIA Positive results for Small/Large Lesion
            via_positive = get_field_value(patient_data, ['VIA Positive'])
            if not via_inspection or str(via_inspection).strip() == '':
                # If VIA Inspection wasn't done, show dash for lesion fields
                via_small = '-'
                via_large = '-'
            elif via_positive == 'Small Lesion':
                via_small = 'Yes'
                via_large = 'No'
            elif via_positive == 'Large Lesion':
                via_small = 'No'
                via_large = 'Yes'
            else:
                # VIA was done but no lesion detected or field empty
                via_small = '-'
                via_large = '-'
            
            # Breast Examination
            left_breast = get_field_value(patient_data, ['Left Breast Condition'])
            right_breast = get_field_value(patient_data, ['Right Breast Condition'])
            
            # Determine breast examination result
            left_normal = left_breast == 'Normal'
            right_normal = right_breast == 'Normal'
            left_abnormal = left_breast == 'Abnormal'
            right_abnormal = right_breast == 'Abnormal'
            
            if left_normal and right_normal:
                breast_exam = 'Normal'
            elif left_abnormal and right_abnormal:
                breast_exam = 'Both Abnormal'
            elif left_abnormal:
                breast_exam = 'Left Abnormal'
            elif right_abnormal:
                breast_exam = 'Right Abnormal'
            else:
                breast_exam = 'Normal'
            
            # Surgeries - check surgical procedure field
            surgical_procedure = get_field_value(patient_data, ['Surgical Procedure'])
            
            # Define major vs minor procedures based on exact form options
            major_procedures = [
                'Appendectomy', 'Cervical Repair', 'Cystectomy', 'Hernioplasty', 
                'Laparotomy', 'Lumpectomy', 'Myomectomy', 'Total Abdominal Hysterectomy (TAH)',
                'Total Abdominal Hysterectomy with Bilateral Salpingo-Oophorectomy (TAH + BSO)', 
                'Thyroidectomy', 'Total Vaginal Hysterectomy (TVH)'
            ]
            
            minor_procedures = [
                'Colporrhaphy', 'Excision', 'Fissurectomy', 'Hemorrhoidectomy', 'Herniorrhaphy',
                'Wide Local Excision (WLE)', 'Marsupialization', 'Incision and Drainage (I&D)'
            ]
            
            surgery_performed = 'No'
            if surgical_procedure:
                procedure_list = surgical_procedure if isinstance(surgical_procedure, list) else [surgical_procedure]
                for procedure in procedure_list:
                    if procedure in major_procedures:
                        surgery_performed = 'Major'
                        break
                    elif procedure in minor_procedures:
                        surgery_performed = 'Minor'
                        break
            

            
            # Diagnosis - get from exact field name
            diagnosis_raw = get_field_value(patient_data, ['Diagnosis'])
            diagnosis = ''
            if diagnosis_raw:
                if isinstance(diagnosis_raw, list):
                    # Filter out NIL and VIA-related duplicates
                    filtered_diagnoses = [d for d in diagnosis_raw if d not in ['NIL', 'VIA Positive (Small Lesion)']]
                    diagnosis = ', '.join(filtered_diagnoses) if filtered_diagnoses else ''
                else:
                    diagnosis = str(diagnosis_raw).strip() if diagnosis_raw != 'NIL' else ''
            
            # Treatment Plan
            plan = build_gyne_treatment_plan(patient_data)
            
            # Contact (Phone) and Address (Ward) - use exact field names
            contact = get_field_value(patient_data, ['Phone Number'])
            address = get_field_value(patient_data, ['Ward'])
            
            # Build row
            row = [
                name or '',
                age or '',
                cx_visual,
                via_neg,
                via_small,
                via_large,
                breast_exam,
                surgery_performed,
                diagnosis or '',
                plan or '',
                contact or '',
                address or ''
            ]
            data.append(row)
        
        # GYNE-specific column widths (optimized for 12 columns)
        col_widths = [
            1.1 * inch,  # Name
            0.5 * inch,  # Age
            0.8 * inch,  # Suspect for Cervical CA
            0.6 * inch,  # VIA NEG
            0.7 * inch,  # VIA Small Lesion
            0.7 * inch,  # VIA Large Lesion
            0.8 * inch,  # Breast Examination
            0.7 * inch,  # Surgeries
            1.2 * inch,  # Diagnosis (increased width since infertility now goes here)
            1.1 * inch,  # Plan
            0.8 * inch,  # Contact
            0.8 * inch,  # Address
        ]
        
        # Add table title
        table_title_style = ParagraphStyle(
            'TableTitle',
            parent=styles['Heading2'],
            fontSize=14,
            alignment=1,
            textColor=colors.black,
            fontName='Times-Bold',
            spaceAfter=15
        )
        table_title = Paragraph("GYNE PATIENTS SUMMARY", table_title_style)
        elements.append(table_title)
        
        # Process data for proper text wrapping
        processed_data = []
        for i, row in enumerate(data):
            if i == 0:  # Header row
                processed_data.append(row)
            else:
                processed_row = []
                for j, cell in enumerate(row):
                    # Apply paragraph styling to long text columns
                    if j in [0, 8, 9, 10, 11]:  # Name, Diagnosis, Plan, Contact, Address
                        if cell and len(str(cell)) > 10:
                            cell_style = ParagraphStyle(
                                'CellText',
                                parent=styles['Normal'],
                                fontName='Times-Roman',
                                fontSize=8,
                                leading=9
                            )
                            processed_row.append(Paragraph(str(cell), cell_style))
                        else:
                            processed_row.append(cell or '')
                    else:
                        processed_row.append(cell or '')
                processed_data.append(processed_row)
        
        table = Table(processed_data, repeatRows=1, colWidths=col_widths)
        table.setStyle(TableStyle([
            # Header styling
            ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            
            # Data rows styling
            ('FONTNAME', (0, 1), (-1, -1), 'Times-Roman'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            
            # Alignment for each column
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),    # Name
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),  # Age
            ('ALIGN', (2, 1), (7, -1), 'CENTER'),  # All Yes/No columns
            ('ALIGN', (8, 1), (8, -1), 'LEFT'),    # Diagnosis
            ('ALIGN', (9, 1), (9, -1), 'LEFT'),    # Plan
            ('ALIGN', (10, 1), (10, -1), 'CENTER'), # Contact
            ('ALIGN', (11, 1), (11, -1), 'LEFT'),  # Address
            
            # Vertical alignment
            ('VALIGN', (0, 1), (-1, -1), 'TOP'),
            
            # Padding
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('LEFTPADDING', (0, 1), (-1, -1), 4),
            ('RIGHTPADDING', (0, 1), (-1, -1), 4),
            
            # Grid and borders
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
        ]))
        
        elements.append(table)
        
        # Add GYNE-specific summary statistics
        add_gyne_summary_statistics(elements, patients, styles, project_id, start_date, end_date)
    
    return elements

def add_summary_statistics(elements, patients, styles, project_id, start_date, end_date, programme_name, show_total_percentage=True):
    """Add clean summary statistics to PDF with total percentages"""
    from reportlab.platypus import Spacer, Table, TableStyle, Paragraph
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    
    # Add spacing and title
    elements.append(Spacer(1, 30))
    
    # Create clean title style
    summary_title_style = ParagraphStyle(
        'SummaryTitle',
        parent=styles['Heading1'],
        fontSize=14,
        alignment=1,  # Center
        textColor=colors.black,
        spaceAfter=20,
        fontName='Times-Bold'
    )
    summary_title = Paragraph("SUMMARY STATISTICS", summary_title_style)
    elements.append(summary_title)
    
    # Calculate statistics for current report
    total_patients = len(patients)
    cataract_patients = 0
    immature_cataract_patients = 0
    pterygium_patients = 0
    chalazion_patients = 0
    foreign_body_patients = 0
    trichiasis_patients = 0
    reading_glasses_count = 0
    surgical_referrals = 0
    
    for patient in patients:
        patient_data = patient.get('data', {})
        
        # Count cataract patients (separate immature from regular cataracts) and other diagnoses
        diagnosis = get_field_value(patient_data, [
            'diagnosis', 'diagnoses', 'Diagnosis', 'Diagnoses', 'DIAGNOSIS'
        ])
        if diagnosis:
            # Clean and normalize diagnosis
            diagnosis_clean = diagnosis.strip().lower()
            if 'immature cataract' in diagnosis_clean:
                immature_cataract_patients += 1
            elif 'cataract' in diagnosis_clean:
                cataract_patients += 1
            elif 'pterygium' in diagnosis_clean:
                pterygium_patients += 1
            elif 'chalazion' in diagnosis_clean:
                chalazion_patients += 1
            elif 'foreign body' in diagnosis_clean:
                foreign_body_patients += 1
            elif 'trichiasis' in diagnosis_clean:
                trichiasis_patients += 1
        
        # Count reading glasses prescriptions
        treatment_plan = build_treatment_plan(patient_data, programme_name)
        if 'READING GLASS' in treatment_plan:
            reading_glasses_count += 1
        
        # Count surgical referrals (FREE EYE CAMPS specific)
        if 'FREE EYE CAMPS' in programme_name.upper():
            # For FREE EYE CAMPS, only count "Referral for Surgery" field when value is "Yes"
            referral_surgery = get_field_value(patient_data, [
                'Referral for Surgery', 'referral for surgery', 'Referral for surgery'
            ])
            
            if referral_surgery and referral_surgery.strip().lower() == 'yes':
                surgical_referrals += 1
        else:
            # Generic logic for other programmes
            surgical_procedure = get_field_value(patient_data, [
                'Surgical Procedure', 'surgical procedure', 'surgery', 'procedure'
            ])
            referral_surgery = get_field_value(patient_data, [
                'Referral for Surgery', 'referral for surgery', 'surgery referral'
            ])
            
            if ((surgical_procedure and surgical_procedure.strip().lower() not in ['no', 'none', 'n/a']) or 
                (referral_surgery and referral_surgery.strip().lower() in ['yes', 'y'])):
                surgical_referrals += 1
    
    # Get total statistics across ALL doctors for percentage calculation
    all_doctors_patients = get_patients_for_report(project_id, "ALL DOCTORS", start_date, end_date)
    total_all_patients = len(all_doctors_patients)
    total_all_cataracts = 0
    total_all_immature_cataracts = 0
    total_all_pterygium = 0
    total_all_chalazion = 0
    total_all_foreign_body = 0
    total_all_trichiasis = 0
    total_all_reading_glasses = 0
    total_all_surgical_referrals = 0
    
    for patient in all_doctors_patients:
        patient_data = patient.get('data', {})
        
        # Count cataract patients (separate immature from regular cataracts) and other diagnoses
        diagnosis = get_field_value(patient_data, [
            'diagnosis', 'diagnoses', 'Diagnosis', 'Diagnoses', 'DIAGNOSIS'
        ])
        if diagnosis:
            diagnosis_clean = diagnosis.strip().lower()
            if 'immature cataract' in diagnosis_clean:
                total_all_immature_cataracts += 1
            elif 'cataract' in diagnosis_clean:
                total_all_cataracts += 1
            elif 'pterygium' in diagnosis_clean:
                total_all_pterygium += 1
            elif 'chalazion' in diagnosis_clean:
                total_all_chalazion += 1
            elif 'foreign body' in diagnosis_clean:
                total_all_foreign_body += 1
            elif 'trichiasis' in diagnosis_clean:
                total_all_trichiasis += 1
        
        # Count reading glasses prescriptions
        treatment_plan = build_treatment_plan(patient_data, programme_name)
        if 'READING GLASS' in treatment_plan:
            total_all_reading_glasses += 1
        
        # Count surgical referrals (FREE EYE CAMPS specific)
        if 'FREE EYE CAMPS' in programme_name.upper():
            # For FREE EYE CAMPS, only count "Referral for Surgery" field when value is "Yes"
            referral_surgery = get_field_value(patient_data, [
                'Referral for Surgery', 'referral for surgery', 'Referral for surgery'
            ])
            
            if referral_surgery and referral_surgery.strip().lower() == 'yes':
                total_all_surgical_referrals += 1
        else:
            # Generic logic for other programmes
            surgical_procedure = get_field_value(patient_data, [
                'Surgical Procedure', 'surgical procedure', 'surgery', 'procedure'
            ])
            referral_surgery = get_field_value(patient_data, [
                'Referral for Surgery', 'referral for surgery', 'surgery referral'
            ])
            
            if ((surgical_procedure and surgical_procedure.strip().lower() not in ['no', 'none', 'n/a']) or 
                (referral_surgery and referral_surgery.strip().lower() in ['yes', 'y'])):
                total_all_surgical_referrals += 1
    
    # Helper function for safe percentage calculation
    def safe_percentage(count, total):
        return f"{count/total*100:.1f}%" if total > 0 else "0%"
    
    # Create summary table with Paragraph objects for better text wrapping
    from reportlab.lib.styles import ParagraphStyle
    
    # Define cell text styles for better wrapping
    header_cell_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=10,
        fontName='Times-Bold',
        alignment=1,  # Center
        textColor=colors.black,
        leading=12
    )
    
    metric_cell_style = ParagraphStyle(
        'MetricCell', 
        parent=styles['Normal'],
        fontSize=9,
        fontName='Times-Bold',
        alignment=0,  # Left
        textColor=colors.black,
        leading=11,
        leftIndent=6,
        rightIndent=6
    )
    
    data_cell_style = ParagraphStyle(
        'DataCell',
        parent=styles['Normal'], 
        fontSize=9,
        fontName='Times-Roman',
        alignment=1,  # Center
        textColor=colors.black,
        leading=11
    )
    
    # Create summary table data with Paragraph objects for proper text wrapping
    if show_total_percentage:
        header_row = [
            Paragraph('METRIC', header_cell_style),
            Paragraph('COUNT', header_cell_style), 
            Paragraph('PERCENTAGE', header_cell_style),
            Paragraph('TOTAL<br/>PERCENTAGE', header_cell_style)
        ]
        col_widths = [3.2*inch, 1.0*inch, 1.1*inch, 1.3*inch]
    else:
        header_row = [
            Paragraph('METRIC', header_cell_style),
            Paragraph('COUNT', header_cell_style), 
            Paragraph('PERCENTAGE', header_cell_style)
        ]
        col_widths = [4.2*inch, 1.5*inch, 1.5*inch]
    
    # Define data rows for eye camps
    rows_data = [
        ('Total Patients', total_patients, '100.0%', total_all_patients),
        ('Cataract Cases', cataract_patients, safe_percentage(cataract_patients, total_patients), total_all_cataracts),
        ('Immature Cataract Cases', immature_cataract_patients, safe_percentage(immature_cataract_patients, total_patients), total_all_immature_cataracts),
        ('Pterygium Cases', pterygium_patients, safe_percentage(pterygium_patients, total_patients), total_all_pterygium),
        ('Chalazion Cases', chalazion_patients, safe_percentage(chalazion_patients, total_patients), total_all_chalazion),
        ('Foreign Body Cases', foreign_body_patients, safe_percentage(foreign_body_patients, total_patients), total_all_foreign_body),
        ('Trichiasis Cases', trichiasis_patients, safe_percentage(trichiasis_patients, total_patients), total_all_trichiasis),
        ('Reading Glasses Prescribed', reading_glasses_count, safe_percentage(reading_glasses_count, total_patients), total_all_reading_glasses),
        ('Surgical Referrals', surgical_referrals, safe_percentage(surgical_referrals, total_patients), total_all_surgical_referrals)
    ]
    
    # Build table data with conditional total percentage column
    summary_data = [header_row]
    for label, count, percentage, total_count in rows_data:
        if show_total_percentage:
            row = [
                Paragraph(label, metric_cell_style),
                Paragraph(str(count), data_cell_style),
                Paragraph(percentage, data_cell_style),
                Paragraph(safe_percentage(count, total_count), data_cell_style)
            ]
        else:
            row = [
                Paragraph(label, metric_cell_style),
                Paragraph(str(count), data_cell_style),
                Paragraph(percentage, data_cell_style)
            ]
        summary_data.append(row)
    

    
    # Create summary table with optimized column widths for better text containment
    summary_table = Table(summary_data, colWidths=col_widths)
    summary_table.setStyle(TableStyle([
        # Header row styling
        ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        
        # Data rows styling
        ('VALIGN', (0, 1), (-1, -1), 'TOP'),  # Top align for better text flow
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('LEFTPADDING', (0, 1), (-1, -1), 4),
        ('RIGHTPADDING', (0, 1), (-1, -1), 4),
        
        # Grid and borders - simple black lines
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
    ]))
    
    elements.append(summary_table)

def add_gyne_summary_statistics(elements, patients, styles, project_id, start_date, end_date, show_total_percentage=True):
    """Add GYNE-specific summary statistics to PDF - similar to eye camps implementation"""
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    
    # Add spacing before summary
    elements.append(Spacer(1, 30))
    
    # Summary title
    summary_title_style = ParagraphStyle(
        'SummaryTitle',
        parent=styles['Heading2'],
        fontSize=14,
        alignment=1,
        textColor=colors.black,
        fontName='Times-Bold',
        spaceAfter=15
    )
    summary_title = Paragraph("SUMMARY STATISTICS", summary_title_style)
    elements.append(summary_title)
    
    # Current doctor's patient counts
    total_patients = len(patients)
    suspect_ca = 0
    via_negative = 0
    via_small_lesion = 0
    via_large_lesion = 0
    breast_normal = 0
    breast_abnormal = 0
    major_surgeries = 0
    minor_surgeries = 0
    primary_infertility = 0
    secondary_infertility = 0
    cryotherapy = 0
    
    # Count statistics for current doctor's patients using exact field names
    for patient in patients:
        patient_data = patient.get('data', {})
        
        # Suspect for CA - check if abnormal visual inspection shows "Suspect for Cervical Cancer"
        abnormal_visual = get_field_value(patient_data, ['Abnormal Visual Inspection'])
        if abnormal_visual and 'Suspect for Cervical Cancer' in str(abnormal_visual):
            suspect_ca += 1
        
        # VIA Test results - only count when VIA was actually performed
        via_inspection = get_field_value(patient_data, ['VIA Inspection'])
        if via_inspection and str(via_inspection).strip() != '':
            if via_inspection == 'Negative':
                via_negative += 1
            
            # VIA Positive results - only count when VIA was performed
            via_positive = get_field_value(patient_data, ['VIA Positive'])
            if via_positive == 'Small Lesion':
                via_small_lesion += 1
            elif via_positive == 'Large Lesion':
                via_large_lesion += 1
        
        # Breast Examination - use exact field names and values
        left_breast = get_field_value(patient_data, ['Left Breast Condition'])
        right_breast = get_field_value(patient_data, ['Right Breast Condition'])
        
        left_normal = left_breast == 'Normal'
        right_normal = right_breast == 'Normal'
        left_abnormal = left_breast == 'Abnormal'
        right_abnormal = right_breast == 'Abnormal'
        
        if left_normal and right_normal:
            breast_normal += 1
        elif left_abnormal or right_abnormal:
            breast_abnormal += 1
        
        # Surgeries - use exact Surgical Procedure field (checkbox data)
        surgical_procedure = get_field_value(patient_data, ['Surgical Procedure'])
        
        # Define major vs minor procedures based on exact form options
        major_procedures = [
            'Appendectomy', 'Cervical Repair', 'Cystectomy', 'Hernioplasty', 
            'Laparotomy', 'Lumpectomy', 'Myomectomy', 'Total Abdominal Hysterectomy (TAH)',
            'Total Abdominal Hysterectomy with Bilateral Salpingo-Oophorectomy (TAH + BSO)', 
            'Thyroidectomy', 'Total Vaginal Hysterectomy (TVH)'
        ]
        
        minor_procedures = [
            'Colporrhaphy', 'Excision', 'Fissurectomy', 'Hemorrhoidectomy', 'Herniorrhaphy',
            'Wide Local Excision (WLE)', 'Marsupialization', 'Incision and Drainage (I&D)'
        ]
        
        if surgical_procedure:
            # Handle checkbox data - convert to list and check each procedure
            procedure_list = surgical_procedure if isinstance(surgical_procedure, list) else [surgical_procedure]
            surgery_found = False
            for procedure in procedure_list:
                procedure_str = str(procedure).strip()
                if procedure_str in major_procedures:
                    major_surgeries += 1
                    surgery_found = True
                    break
                elif procedure_str in minor_procedures:
                    minor_surgeries += 1
                    surgery_found = True
                    break
        
        # Infertility - check diagnosis field (checkbox data) for infertility values
        diagnosis = get_field_value(patient_data, ['Diagnosis'])
        if diagnosis:
            # Handle both string and list formats from checkbox data
            diagnosis_str = ''
            if isinstance(diagnosis, list):
                diagnosis_str = ' '.join(str(d) for d in diagnosis).lower()
            else:
                diagnosis_str = str(diagnosis).lower()
            
            # Check for infertility (case insensitive, flexible matching)
            if 'primary infertility' in diagnosis_str:
                primary_infertility += 1
            elif 'secondary infertility' in diagnosis_str:
                secondary_infertility += 1
        
        # Cryotherapy - check Treatment Plan field (checkbox data)
        treatment_plan = get_field_value(patient_data, ['Treatment Plan'])
        if treatment_plan:
            # Handle checkbox data properly
            plan_str = ''
            if isinstance(treatment_plan, list):
                plan_str = ' '.join(str(p) for p in treatment_plan).lower()
            else:
                plan_str = str(treatment_plan).lower()
            
            if 'cryotherapy' in plan_str:
                cryotherapy += 1

    # Get ALL patients for this project/date range to calculate totals
    all_doctors_patients = get_patients_for_report(project_id, "ALL DOCTORS", start_date, end_date)
    
    # Calculate totals across all doctors
    total_all_patients = len(all_doctors_patients)
    total_all_suspect_ca = 0
    total_all_via_negative = 0
    total_all_via_small_lesion = 0
    total_all_via_large_lesion = 0
    total_all_breast_normal = 0
    total_all_breast_abnormal = 0
    total_all_major_surgeries = 0
    total_all_minor_surgeries = 0
    total_all_primary_infertility = 0
    total_all_secondary_infertility = 0
    total_all_cryotherapy = 0
    
    for patient in all_doctors_patients:
        patient_data = patient.get('data', {})
        
        # Same improved counting logic for all patients
        abnormal_visual = get_field_value(patient_data, ['Abnormal Visual Inspection'])
        if abnormal_visual and 'Suspect for Cervical Cancer' in str(abnormal_visual):
            total_all_suspect_ca += 1
        
        via_inspection = get_field_value(patient_data, ['VIA Inspection'])
        if via_inspection and str(via_inspection).strip() != '':
            if via_inspection == 'Negative':
                total_all_via_negative += 1
            
            # VIA Positive results - only count when VIA was performed
            via_positive = get_field_value(patient_data, ['VIA Positive'])
            if via_positive == 'Small Lesion':
                total_all_via_small_lesion += 1
            elif via_positive == 'Large Lesion':
                total_all_via_large_lesion += 1
        
        left_breast = get_field_value(patient_data, ['Left Breast Condition'])
        right_breast = get_field_value(patient_data, ['Right Breast Condition'])
        
        left_normal = left_breast == 'Normal'
        right_normal = right_breast == 'Normal'
        left_abnormal = left_breast == 'Abnormal'
        right_abnormal = right_breast == 'Abnormal'
        
        if left_normal and right_normal:
            total_all_breast_normal += 1
        elif left_abnormal or right_abnormal:
            total_all_breast_abnormal += 1
        
        # Surgery counting using exact Surgical Procedure field (checkbox data)
        surgical_procedure = get_field_value(patient_data, ['Surgical Procedure'])
        
        major_procedures = [
            'Appendectomy', 'Cervical Repair', 'Cystectomy', 'Hernioplasty', 
            'Laparotomy', 'Lumpectomy', 'Myomectomy', 'Total Abdominal Hysterectomy (TAH)',
            'Total Abdominal Hysterectomy with Bilateral Salpingo-Oophorectomy (TAH + BSO)', 
            'Thyroidectomy', 'Total Vaginal Hysterectomy (TVH)'
        ]
        
        minor_procedures = [
            'Colporrhaphy', 'Excision', 'Fissurectomy', 'Hemorrhoidectomy', 'Herniorrhaphy',
            'Wide Local Excision (WLE)', 'Marsupialization', 'Incision and Drainage (I&D)'
        ]
        
        if surgical_procedure:
            # Handle checkbox data - convert to list and check each procedure
            procedure_list = surgical_procedure if isinstance(surgical_procedure, list) else [surgical_procedure]
            surgery_found = False
            for procedure in procedure_list:
                procedure_str = str(procedure).strip()
                if procedure_str in major_procedures:
                    total_all_major_surgeries += 1
                    surgery_found = True
                    break
                elif procedure_str in minor_procedures:
                    total_all_minor_surgeries += 1
                    surgery_found = True
                    break
        
        # Infertility counting from diagnosis field (checkbox data)
        diagnosis = get_field_value(patient_data, ['Diagnosis'])
        if diagnosis:
            # Handle both string and list formats from checkbox data
            diagnosis_str = ''
            if isinstance(diagnosis, list):
                diagnosis_str = ' '.join(str(d) for d in diagnosis).lower()
            else:
                diagnosis_str = str(diagnosis).lower()
            
            # Check for infertility (case insensitive, flexible matching)
            if 'primary infertility' in diagnosis_str:
                total_all_primary_infertility += 1
            elif 'secondary infertility' in diagnosis_str:
                total_all_secondary_infertility += 1
        
        # Cryotherapy counting from Treatment Plan field (checkbox data)
        treatment_plan = get_field_value(patient_data, ['Treatment Plan'])
        if treatment_plan:
            # Handle checkbox data properly
            plan_str = ''
            if isinstance(treatment_plan, list):
                plan_str = ' '.join(str(p) for p in treatment_plan).lower()
            else:
                plan_str = str(treatment_plan).lower()
            
            if 'cryotherapy' in plan_str:
                total_all_cryotherapy += 1
    
    # Helper function for safe percentage calculation
    def safe_percentage(count, total):
        return f"{count/total*100:.1f}%" if total > 0 else "0%"
    
    # Create styles for table cells
    header_cell_style = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontSize=10,
        fontName='Times-Bold',
        alignment=1,  # Center
        textColor=colors.black,
        leading=12
    )
    
    metric_cell_style = ParagraphStyle(
        'MetricCell', 
        parent=styles['Normal'],
        fontSize=9,
        fontName='Times-Bold',
        alignment=0,  # Left
        textColor=colors.black,
        leading=11,
        leftIndent=6,
        rightIndent=6
    )
    
    data_cell_style = ParagraphStyle(
        'DataCell',
        parent=styles['Normal'], 
        fontSize=9,
        fontName='Times-Roman',
        alignment=1,  # Center
        textColor=colors.black,
        leading=11
    )
    
    # Create summary table data with proper structure like eye camps
    if show_total_percentage:
        header_row = [
            Paragraph('METRIC', header_cell_style),
            Paragraph('COUNT', header_cell_style), 
            Paragraph('PERCENTAGE', header_cell_style),
            Paragraph('TOTAL<br/>PERCENTAGE', header_cell_style)
        ]
        col_widths = [3.2*inch, 1.0*inch, 1.1*inch, 1.3*inch]
    else:
        header_row = [
            Paragraph('METRIC', header_cell_style),
            Paragraph('COUNT', header_cell_style), 
            Paragraph('PERCENTAGE', header_cell_style)
        ]
        col_widths = [4.2*inch, 1.5*inch, 1.5*inch]
    
    # Define data rows
    rows_data = [
        ('Total Patients', total_patients, '100.0%', total_all_patients),
        ('Suspect for Cervical CA', suspect_ca, safe_percentage(suspect_ca, total_patients), total_all_suspect_ca),
        ('VIA Negative', via_negative, safe_percentage(via_negative, total_patients), total_all_via_negative),
        ('VIA Positive with Small Lesion', via_small_lesion, safe_percentage(via_small_lesion, total_patients), total_all_via_small_lesion),
        ('VIA Positive with Large Lesion', via_large_lesion, safe_percentage(via_large_lesion, total_patients), total_all_via_large_lesion),
        ('Normal Breast Examination', breast_normal, safe_percentage(breast_normal, total_patients), total_all_breast_normal),
        ('Abnormal Breast Examination', breast_abnormal, safe_percentage(breast_abnormal, total_patients), total_all_breast_abnormal),
        ('Major Surgeries', major_surgeries, safe_percentage(major_surgeries, total_patients), total_all_major_surgeries),
        ('Minor Surgeries', minor_surgeries, safe_percentage(minor_surgeries, total_patients), total_all_minor_surgeries),
        ('Primary Infertility', primary_infertility, safe_percentage(primary_infertility, total_patients), total_all_primary_infertility),
        ('Secondary Infertility', secondary_infertility, safe_percentage(secondary_infertility, total_patients), total_all_secondary_infertility),
        ('Cryotherapy', cryotherapy, safe_percentage(cryotherapy, total_patients), total_all_cryotherapy)
    ]
    
    # Build table data with conditional total percentage column
    summary_data = [header_row]
    for label, count, percentage, total_count in rows_data:
        if show_total_percentage:
            row = [
                Paragraph(label, metric_cell_style),
                Paragraph(str(count), data_cell_style),
                Paragraph(percentage, data_cell_style),
                Paragraph(safe_percentage(count, total_count), data_cell_style)
            ]
        else:
            row = [
                Paragraph(label, metric_cell_style),
                Paragraph(str(count), data_cell_style),
                Paragraph(percentage, data_cell_style)
            ]
        summary_data.append(row)
    
    # Create summary table with same structure as eye camps
    summary_table = Table(summary_data, colWidths=col_widths)
    summary_table.setStyle(TableStyle([
        # Header row styling
        ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        
        # Data rows styling
        ('VALIGN', (0, 1), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('LEFTPADDING', (0, 1), (-1, -1), 4),
        ('RIGHTPADDING', (0, 1), (-1, -1), 4),
        
        # Grid and borders
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
    ]))
    
    elements.append(summary_table)

def generate_programme_summary_pdf(patients, programme_name, start_date, end_date, project_id):
    """Generate Programme Summary PDF with just the summary statistics table"""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from io import BytesIO
    import datetime
    import os
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=50, bottomMargin=18)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Add MDF logo
    logo_path = os.path.join(os.path.dirname(__file__), 'MDF.png')
    if os.path.exists(logo_path):
        try:
            logo = Image(logo_path, width=1.0*inch, height=0.8*inch, kind='proportional')
            logo.hAlign = 'CENTER'
            elements.append(logo)
            elements.append(Spacer(1, 15))
        except Exception as e:
            print(f"Could not load logo: {str(e)}")
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Title styling
    title_style = ParagraphStyle(
        'ReportTitle', 
        parent=styles['Heading1'], 
        fontSize=20, 
        alignment=1,
        textColor=colors.black,
        fontName='Times-Bold',
        spaceAfter=20
    )
    
    # Programme Summary title
    if 'OBSTETRICS' in programme_name.upper() and 'GYNECOLOGY' in programme_name.upper():
        title = Paragraph(f"GYNECOLOGY PROGRAMME SUMMARY<br/><font size='16'>{programme_name}</font>", title_style)
    else:
        title = Paragraph(f"PROGRAMME SUMMARY<br/><font size='16'>{programme_name}</font>", title_style)
    elements.append(title)
    
    # Report details
    if start_date == end_date:
        date_str = start_date.strftime('%B %d, %Y')
    else:
        date_str = f"{start_date.strftime('%B %d, %Y')} - {end_date.strftime('%B %d, %Y')}"
    
    # Create header info
    generated_at = datetime.datetime.now(EAT).strftime('%B %d, %Y at %I:%M %p EAT')
    info_style = ParagraphStyle(
        'InfoStyle',
        parent=styles['Normal'],
        fontSize=12,
        alignment=1,
        spaceAfter=30
    )
    
    info_text = f"<b>Period:</b> {date_str}<br/><b>Total Patients:</b> {len(patients)}<br/><b>Generated:</b> {generated_at}"
    info_para = Paragraph(info_text, info_style)
    elements.append(info_para)
    
    # Add appropriate summary statistics based on programme type
    if 'OBSTETRICS' in programme_name.upper() and 'GYNECOLOGY' in programme_name.upper():
        # Add GYNE-specific summary statistics (without total percentage column)
        add_gyne_summary_statistics(elements, patients, styles, project_id, start_date, end_date, show_total_percentage=False)
    else:
        # Add general summary statistics (without total percentage column)
        add_summary_statistics(elements, patients, styles, project_id, start_date, end_date, programme_name, show_total_percentage=False)
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
