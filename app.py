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
                          'form_permissions', 'log_activities', 'patients']
        
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
        all_forms_response = supabase.table('forms').select('id, title').eq('project_id', project_id).order('created_at').execute()
        if not all_forms_response.data or len(all_forms_response.data) == 0:
            print(f"No forms found for project {project_id} when checking if form {form_id} is first")
            get_form_is_first.cache[form_id] = False
            return False
        
        # Check if form is the first created in its project
        is_first_by_order = all_forms_response.data[0]['id'] == form_id
        
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
        return redirect(url_for('projects'))
    
    project = project_response.data[0]
    # Remove camp_date if it exists in the fetched data
    project.pop('camp_date', None)
    
    # Get forms for this project, excluding archived forms
    forms_response = supabase.table('forms').select('*').eq('project_id', project_id).eq('is_archived', False).order('created_at').execute()
    forms = forms_response.data
    
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
        
        # Get all approved users for the dropdown
        users_response = supabase.table('users').select('*').eq('is_approved', True).execute()
        users = users_response.data
    
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
        labels = request.form.getlist('field_labels[]')
        types = request.form.getlist('field_types[]')
        options_list = request.form.getlist('field_options[]')
        location_identifiers = request.form.getlist('location_field_identifier[]')
        required_fields = request.form.getlist('field_required[]')
        allow_other_fields = request.form.getlist('allow_other[]')
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        if not labels:
            flash('At least one field is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
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
            fields.append(field)
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
    all_forms_response = supabase.table('forms').select('id').eq('project_id', form['project_id']).order('created_at').execute()
    is_first_form = False
    
    # Calculate form_index for the waitlist feature
    form_indices = {}
    if all_forms_response.data and len(all_forms_response.data) > 0:
        # Check if current form is the first one created
        is_first_form = all_forms_response.data[0]['id'] == form_id
        # Map form IDs to their positions in the sequence
        form_indices = {f['id']: idx for idx, f in enumerate(all_forms_response.data)}
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
    
    # Collect form data and validate required fields
    form_data = {}
    validation_errors = []
    
    for field in form['fields']:
        field_label = field['label']
        field_value = None
        
        if field['type'] in ['dropdown', 'radio']:
            field_value = request.form.get(field_label)
        elif field['type'] == 'checkbox':
            field_value = request.form.getlist(field_label)
        else:
            field_value = request.form.get(field_label)
        
        # Validate required fields
        if field.get('required', False) and (field_value is None or field_value == ''):
            validation_errors.append(f"Field '{field_label}' is required")
        
        form_data[field_label] = field_value
    
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
    
    return render_template('user_dashboard.html', projects=projects, accessible_forms=accessible_forms)

@app.route('/programs')
@login_required
def program_list():
    """List all available programs before showing dataset view"""
    # Get all projects
    projects_response = supabase.table('projects').select('*').order('name').execute()
    projects = projects_response.data if projects_response.data else []
    
    # Log activity
    log_activity('view', 'programs_list', None, "Viewed programs list for dataset selection")
    
    return render_template('projects_list.html', 
                         projects=projects,
                         is_dataset_view=True)

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
    
    # If no project_id is provided, redirect to program list
    if not project_id:
        return redirect(url_for('program_list'))
    
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

    # Track which fields come from first/registration forms for proper display
    registration_form_fields = set()

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
                            print(f"Added registration field: {label}")

    # Also collect fields from all registration forms in the database
    # This ensures we show registration data even if the registration form isn't in the current project
    if project_id:
        print("Looking for registration forms in other projects for cross-program data display")
        # Get all form IDs that are first/registration forms in the system
        registration_form_ids = []
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id) and form.get('project_id') != project_id:
                registration_form_ids.append(form_id)
                print(f"Found external registration form: {form_id} in project {form.get('project_id')}")
        
        # For each registration form, add its fields to our list if not already present
        for reg_form_id in registration_form_ids:
            reg_form_response = supabase.table('forms').select('fields').eq('id', reg_form_id).execute()
            if reg_form_response.data:
                reg_form = reg_form_response.data[0]
                reg_fields_json = reg_form.get('fields', '[]')
                try:
                    if isinstance(reg_fields_json, str):
                        reg_parsed_fields = json.loads(reg_fields_json)
                    else:
                        reg_parsed_fields = reg_fields_json

                    if isinstance(reg_parsed_fields, list):
                        for field in reg_parsed_fields:
                            if isinstance(field, dict) and 'label' in field:
                                label = field['label']
                                normalized_label = label.lower().strip().replace(' ', '_')
                                if normalized_label not in seen_normalized_fields:
                                    ordered_fields.append(label)
                                    seen_normalized_fields.add(normalized_label)
                                    field_label_map[normalized_label] = label
                                    registration_form_fields.add(normalized_label)
                                    print(f"Added external registration field: {label}")
                except Exception as e:
                    print(f"Error processing registration form fields: {str(e)}")
                    
    # Now continue with rest of function using modified ordered_fields

    # 3. Get all submissions based on filters (project or form)
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # If we have a project filter, make sure we also get registration forms from ALL projects
    # This allows us to pull in registration data from other programs
    all_registration_form_ids = []
    if project_id:
        print("Looking for ALL registration forms across ALL projects for cross-program data")
        # Query all forms
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id):
                # Include registration forms from all projects
                if form_id not in submission_form_ids:
                    all_registration_form_ids.append(form_id)
                    print(f"Including registration form: {form.get('title')} (ID: {form_id}) from project: {form.get('project_id')}")
        
        # Expand our submission_form_ids to include registration forms from all projects
        if all_registration_form_ids:
            print(f"Adding {len(all_registration_form_ids)} registration forms from other projects")
            submission_form_ids.extend(all_registration_form_ids)

    # Modified query to get submissions even if no forms match the criteria
    query = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))')
    
    if submission_form_ids: 
        # Filter by the forms we care about if we have matching forms
        query = query.in_('form_id', submission_form_ids)
    elif form_id:
        # If a specific form is requested but not found in the system, use its ID directly
        query = query.eq('form_id', form_id)
    elif project_id:
        # If filtering by project and no forms were found, try to match via the form's project_id in joined data
        # This works if forms data is accessible via the join
        query = query.eq('forms.project_id', project_id)
        
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
    
    # If no submissions were found through the form-based filters,
    # try a direct query on form_submissions without form filtering
    if not submissions and (form_id or project_id):
        print("No submissions found with form filters. Trying direct query.")
        try:
            # Direct query without form filtering
            backup_query = supabase.table('form_submissions').select('*')
            backup_response = backup_query.execute()
            submissions = backup_response.data
            print(f"Direct query found {len(submissions)} submissions")
        except Exception as e:
            print(f"Error in backup query: {str(e)}")
            submissions = []

    # 4. Filter submissions based on search term (if any)
    if search_term:
        try:
            filtered_submissions = []
            search_lower = search_term.lower()
            for sub in submissions:
                # Check patient_id first
                if search_lower in str(sub.get('patient_id', '')).lower():
                    filtered_submissions.append(sub)
                    continue 
                
                # Only search in data if it exists and is a dictionary
                if sub.get('data') and isinstance(sub['data'], dict):
                    match_found = False
                    for value in sub['data'].values():
                        if isinstance(value, list):
                            if any(search_lower in str(item).lower() for item in value if item is not None):
                                match_found = True
                                break
                        elif value is not None and search_lower in str(value).lower():
                            match_found = True
                            break
                    
                    if match_found:
                        filtered_submissions.append(sub)
            
            submissions = filtered_submissions
            print(f"Found {len(submissions)} submissions after search for '{search_term}'")
        except Exception as e:
            print(f"Error during search filtering: {str(e)}")
            # If search fails, fall back to using all submissions before search
            print(f"Search failed, using all submissions")
    
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
        
        if patient_id not in patient_data:
            patient_data[patient_id] = {
                'patient_id': patient_id,
                'submissions': [],
                'has_project_submissions': False,  # Flag to track if patient has submissions in this project
                'has_non_registration_submissions': False  # Flag to track if patient has submissions in non-registration forms
            }
        
        # Only add submissions to the patient record if they're from the selected project or no project filter is active
        patient_data[patient_id]['submissions'].append(submission)
        
        # Mark if this submission belongs to the selected project
        if should_process_fields:
            patient_data[patient_id]['has_project_submissions'] = True
            
            # Mark if this is a non-registration form submission
            if not is_registration_form:
                patient_data[patient_id]['has_non_registration_submissions'] = True
        
        # Collect all unique field keys from actual data, but only if they belong to the selected project
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                # Ensure field_label_map has original casing even for data-only fields
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
                    
    # If a project is selected, filter out patients who don't meet criteria
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            # MODIFIED: Include patients only if they have both registration data AND non-registration submissions
            # OR if they only have non-registration submissions in this project
            if data.get('has_non_registration_submissions', False):
                filtered_patient_data[patient_id] = data
            # Exclude patients who ONLY have registration form submissions
            else:
                print(f"Filtered out patient {patient_id} because they only have registration form submissions")
        
        print(f"Filtered out {len(patient_data) - len(filtered_patient_data)} patients with only registration form submissions")
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
        
        # Get all first/registration forms for this patient from any program
        registration_data = {}
        first_form_ids = set()
        
        # Find all first forms submitted by this patient
        print(f"Looking for registration forms for patient: {patient_id}")
        for submission in data['submissions']:
            form_id = submission.get('form_id')
            if form_id and get_form_is_first(form_id) and submission.get('data'):
                first_form_ids.add(form_id)
                form_title = submission.get('forms', {}).get('title', 'Unknown')
                print(f"Found registration form data from: {form_title} (ID: {form_id}) for patient {patient_id}")
                # Add registration form data with priority to newer submissions
                submission_date = submission.get('created_at', '')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in registration_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        registration_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
                        print(f"  Added registration field: {key}={value}")

        # Sort submissions by date (newest first) to prioritize recent data
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        # First add registration data to merged_data to prioritize it
        # This ensures registration data is preserved and appears first in the data table
        for normalized_key, value in registration_data.items():
            merged_data[normalized_key] = value
            print(f"Added registration data for patient {patient_id}: {normalized_key}={value}")
        
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

    # 10. Get data for filter dropdowns
    # Get all projects
    projects_response = supabase.table('projects').select('*').execute()
    all_projects = projects_response.data
    
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

    # 11. Convert patient_data dictionary to patient_data_list for the template
    # Modify this section to order the fields properly
    patient_data_list = []
    for patient_id, data in patient_data.items():
        if 'merged_data' not in data:
            continue
            
        # 1. Start with patient ID
        patient_row = {'patient_id': patient_id}
        
        # 2. Add registration form fields first
        for field in ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key in registration_form_fields and normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
        
        # 3. Add all other fields
        for field in ordered_fields:
            normalized_key = field.lower().strip().replace(' ', '_')
            if normalized_key not in registration_form_fields and normalized_key in data['merged_data']:
                patient_row[field] = data['merged_data'][normalized_key]
        
        patient_data_list.append(patient_row)

    return render_template('dataset_view.html',
                         patient_data=patient_data,
                         patient_data_list=patient_data_list,  # Add this new parameter
                         # Pass the final ordered list of field labels
                         ordered_fields=final_ordered_fields, 
                         all_fields_for_filter=fields_for_filter,  # Add this missing parameter
                         projects=all_projects,
                         forms=filter_forms, # Use all forms for the filter dropdown
                         field_values=sorted(list(field_values)),
                         selected_project=project_id,
                         selected_project_name=selected_project_name,  # Add this parameter
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
        response = supabase.table('form_submissions').select('*, forms(title, fields, project_id, projects(name))').eq('patient_id', patient_id).execute()
        
        if not response.data:
            print(f"No data found for patient {patient_id}")
            return jsonify({'error': 'Patient not found'}), 404
        
        submissions = response.data
        print(f"Number of submissions found: {len(submissions)}")
        
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
        sorted_submissions = sorted(submissions, key=lambda s: s.get('created_at', ''), reverse=True)
        
        for submission in sorted_submissions:
            form_id = submission.get('form_id')
            if submission.get('data') and form_id:
                submission_date = submission.get('created_at')
                
                for key, value in submission['data'].items():
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
                        ordered_data.append({
                            "field": original_label,
                            "value": data_by_field[normalized_key]
                        })
        
        # Add any fields not associated with a known form
        unknown_fields = [f for f in all_fields if f not in field_to_form_map]
        for normalized_key in sorted(unknown_fields):
            if normalized_key in data_by_field:
                original_label = field_label_map.get(normalized_key, normalized_key)
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
    search_term = request.args.get('search', '').strip()
    
    print(f"Export dataset called with project_id: {project_id}, form_id: {form_id}, search: {search_term}")
    
    # Log the export action with filter details
    log_details = f"Filters - Project: {project_id or 'All'}, Form: {form_id or 'All'}"
    if field_name and field_value:
        log_details += f", Field: {field_name}={field_value}"
    if start_date or end_date:
        log_details += f", Date range: {start_date or 'start'} to {end_date or 'end'}"
    if search_term:
        log_details += f", Search: '{search_term}'"
    log_activity('export', 'dataset', None, log_details)
    
    # This section replicates the dataset_view function to ensure consistency
    
    # 1. Fetch Ordered Forms relevant to the filters
    ordered_forms_data = []
    forms_query = supabase.table('forms').select('*')
    if form_id:
        forms_query = forms_query.eq('id', form_id)
    elif project_id:
        forms_query = forms_query.eq('project_id', project_id).order('created_at', desc=False)
    else:
        forms_query = forms_query.order('project_id', desc=False).order('created_at', desc=False)
    
    forms_response = forms_query.execute()
    if forms_response.data:
        ordered_forms_data = forms_response.data

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {}
    registration_form_fields = set()

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
                            print(f"Export: Added registration field: {label}")
    
    # Also collect fields from all registration forms in the database
    if project_id:
        print("Export: Looking for registration forms in other projects")
        registration_form_ids = []
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id) and form.get('project_id') != project_id:
                registration_form_ids.append(form_id)
                print(f"Export: Found external registration form: {form_id} in project {form.get('project_id')}")
        
        for reg_form_id in registration_form_ids:
            reg_form_response = supabase.table('forms').select('fields').eq('id', reg_form_id).execute()
            if reg_form_response.data:
                reg_form = reg_form_response.data[0]
                reg_fields_json = reg_form.get('fields', '[]')
                try:
                    if isinstance(reg_fields_json, str):
                        reg_parsed_fields = json.loads(reg_fields_json)
                    else:
                        reg_parsed_fields = reg_fields_json

                    if isinstance(reg_parsed_fields, list):
                        for field in reg_parsed_fields:
                            if isinstance(field, dict) and 'label' in field:
                                label = field['label']
                                normalized_label = label.lower().strip().replace(' ', '_')
                                if normalized_label not in seen_normalized_fields:
                                    ordered_fields.append(label)
                                    seen_normalized_fields.add(normalized_label)
                                    field_label_map[normalized_label] = label
                                    registration_form_fields.add(normalized_label)
                                    print(f"Export: Added external registration field: {label}")
                except Exception as e:
                    print(f"Export: Error processing registration form fields: {str(e)}")
    
    # 3. Get all submissions based on filters
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # Include registration forms from ALL projects
    all_registration_form_ids = []
    if project_id:
        print("Export: Including ALL registration forms across ALL projects")
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id):
                if form_id not in submission_form_ids:
                    all_registration_form_ids.append(form_id)
                    print(f"Export: Including registration form: {form.get('title')} (ID: {form_id})")
        
        if all_registration_form_ids:
            print(f"Export: Adding {len(all_registration_form_ids)} registration forms from other projects")
            submission_form_ids.extend(all_registration_form_ids)

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
    
    response = query.execute()
    submissions = response.data
    print(f"Export: Initial submissions fetched: {len(submissions)}")
    
    # Try direct query if no submissions found
    if not submissions and (form_id or project_id):
        print("Export: No submissions found with form filters. Trying direct query.")
        try:
            backup_query = supabase.table('form_submissions').select('*')
            backup_response = backup_query.execute()
            submissions = backup_response.data
            print(f"Export: Direct query found {len(submissions)} submissions")
        except Exception as e:
            print(f"Error in backup query: {str(e)}")
            submissions = []

    # 4. Filter submissions based on search term (if any)
    if search_term:
        try:
            filtered_submissions = []
            search_lower = search_term.lower()
            for sub in submissions:
                if search_lower in str(sub.get('patient_id', '')).lower():
                    filtered_submissions.append(sub)
                    continue 
                
                # Only search in data if it exists and is a dictionary
                if sub.get('data') and isinstance(sub['data'], dict):
                    match_found = False
                    for value in sub['data'].values():
                        if isinstance(value, list):
                            if any(search_lower in str(item).lower() for item in value if item is not None):
                                match_found = True
                                break
                        elif value is not None and search_lower in str(value).lower():
                            match_found = True
                            break
                    
                    if match_found:
                        filtered_submissions.append(sub)
            
            submissions = filtered_submissions
            print(f"Export: Found {len(submissions)} submissions after search for '{search_term}'")
        except Exception as e:
            print(f"Export: Error during search filtering: {str(e)}")
            # If search fails, fall back to using all submissions
            print(f"Export: Search failed, using all {len(submissions)} submissions")
    
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
                'has_project_submissions': False,
                'has_non_registration_submissions': False
            }
        
        patient_data[patient_id]['submissions'].append(submission)
        
        if should_process_fields:
            patient_data[patient_id]['has_project_submissions'] = True
            
            if not is_registration_form:
                patient_data[patient_id]['has_non_registration_submissions'] = True
        
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
                    
    # Filter out patients who only have registration form submissions
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            if data.get('has_non_registration_submissions', False):
                filtered_patient_data[patient_id] = data
            else:
                print(f"Export: Filtered out patient {patient_id} because they only have registration form submissions")
        
        print(f"Export: Filtered out {len(patient_data) - len(filtered_patient_data)} patients with only registration form submissions")
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
    
    # 9. Pre-process patient data to merge values
    for patient_id, data in patient_data.items():
        merged_data = {}
        last_updated = {} 
        
        # Process registration data first
        registration_data = {}
        
        print(f"Export: Processing registration data for patient: {patient_id}")
        for submission in data['submissions']:
            form_id = submission.get('form_id')
            if form_id and get_form_is_first(form_id) and submission.get('data'):
                form_title = submission.get('forms', {}).get('title', 'Unknown')
                print(f"Export: Found registration data from: {form_title} (ID: {form_id})")
                submission_date = submission.get('created_at', '')
                for key, value in submission['data'].items():
                    normalized_key = key.lower().strip().replace(' ', '_')
                    if normalized_key not in registration_data or (submission_date and submission_date > last_updated.get(normalized_key, '')):
                        registration_data[normalized_key] = value
                        if submission_date:
                            last_updated[normalized_key] = submission_date
                        print(f"  Export: Added registration field: {key}={value}")

        # Sort submissions by date (newest first)
        sorted_submissions = sorted(data['submissions'], key=lambda s: s.get('created_at', ''), reverse=True)

        # Add registration data first
        for normalized_key, value in registration_data.items():
            merged_data[normalized_key] = value
            print(f"Export: Added registration data for patient {patient_id}: {normalized_key}={value}")
        
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

    # 10. Convert patient_data dictionary to list for export
    # This follows the exact same pattern as dataset_view
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
    
    if form_id:
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
    if form_id:
        forms_query = forms_query.eq('id', form_id)
    elif project_id:
        forms_query = forms_query.eq('project_id', project_id).order('created_at', desc=False)
    
    forms_response = forms_query.execute()
    if forms_response.data:
        ordered_forms_data = forms_response.data

    # 2. Build ordered_fields list based on form definitions
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {}
    registration_form_fields = set()

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
    
    # Also collect fields from all registration forms in the database
    if project_id:
        registration_form_ids = []
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id) and form.get('project_id') != project_id:
                registration_form_ids.append(form_id)
        
        for reg_form_id in registration_form_ids:
            reg_form_response = supabase.table('forms').select('fields').eq('id', reg_form_id).execute()
            if reg_form_response.data:
                reg_form = reg_form_response.data[0]
                reg_fields_json = reg_form.get('fields', '[]')
                try:
                    if isinstance(reg_fields_json, str):
                        reg_parsed_fields = json.loads(reg_fields_json)
                    else:
                        reg_parsed_fields = reg_fields_json

                    if isinstance(reg_parsed_fields, list):
                        for field in reg_parsed_fields:
                            if isinstance(field, dict) and 'label' in field:
                                label = field['label']
                                normalized_label = label.lower().strip().replace(' ', '_')
                                if normalized_label not in seen_normalized_fields:
                                    ordered_fields.append(label)
                                    seen_normalized_fields.add(normalized_label)
                                    field_label_map[normalized_label] = label
                                    registration_form_fields.add(normalized_label)
                except Exception as e:
                    pass
    
    # 3. Get all submissions based on filters
    submissions = []
    submission_form_ids = [f['id'] for f in ordered_forms_data]

    # Include registration forms from ALL projects
    all_registration_form_ids = []
    if project_id:
        all_forms_response = supabase.table('forms').select('id, title, project_id').execute()
        
        for form in all_forms_response.data:
            form_id = form.get('id')
            if form_id and get_form_is_first(form_id):
                if form_id not in submission_form_ids:
                    all_registration_form_ids.append(form_id)
        
        if all_registration_form_ids:
            submission_form_ids.extend(all_registration_form_ids)

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
            pass
    
    response = query.execute()
    submissions = response.data

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
                'has_project_submissions': False,
                'has_non_registration_submissions': False
            }
        
        patient_data[patient_id]['submissions'].append(submission)
        
        if should_process_fields:
            patient_data[patient_id]['has_project_submissions'] = True
            
            if not is_registration_form:
                patient_data[patient_id]['has_non_registration_submissions'] = True
        
        if submission.get('data') and should_process_fields:
            for key in submission['data'].keys():
                normalized_key = key.lower().strip().replace(' ', '_')
                all_data_fields_normalized.add(normalized_key)
                if normalized_key not in field_label_map:
                    field_label_map[normalized_key] = key
    
    # 5. CRITICAL: Filter out patients who don't have non-registration submissions in this project
    # This ensures analytics only shows patients who actually participated in the selected program
    if project_id and project_form_ids:
        filtered_patient_data = {}
        for patient_id, data in patient_data.items():
            if data.get('has_non_registration_submissions', False):
                filtered_patient_data[patient_id] = data
        
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
        
        # Process registration data first
        registration_data = {}
        
        for submission in data['submissions']:
            form_id = submission.get('form_id')
            if form_id and get_form_is_first(form_id) and submission.get('data'):
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
                            # Standard handling for non-checkbox fields
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
                        
                        # Special handling if either field is a checkbox field
                        if field1_type == 'checkbox' or field2_type == 'checkbox':
                            stats = "<div class='alert alert-warning'>Cross-tabulation with checkbox fields (multiple selection) is not directly supported. Please export the data for more advanced analysis.</div>"
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
                                current_year = datetime.now().year
                                
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
    
    # Render the template with all data
    return render_template('analytics.html',
                          title=title if title else 'Analytics',
                          all_projects=all_projects,
                          forms=forms,
                          selected_project=project_id,
                          selected_form=form_id,
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
    analysis_type = request.args.get('analysis_type')
    field1 = request.args.get('field1')
    field2 = request.args.get('field2')
    export_format = request.args.get('format', 'excel')  # Default to excel
    
    # Get correlation fields (multiple selection)
    correlation_fields = request.args.getlist('correlation_fields[]')
    
    # Log export action
    log_details = f"Export Analytics - Project: {project_id or 'All'}, Form: {form_id or 'All'}, Analysis: {analysis_type}"
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
    
    if form_id:
        form_response = supabase.table('forms').select('title').eq('id', form_id).execute()
        if form_response.data:
            form_title = form_response.data[0]['title']
            filename = f"{filename}_{form_title}"
    
    if analysis_type:
        filename = f"{filename}_{analysis_type}"
    
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
                    ct = pd.crosstab(df[field1], df[field2])
                    ct.to_csv(output)
                except TypeError:
                    # Handle unhashable types like lists
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
                        ct = pd.crosstab(df[field1], df[field2])
                        ct.to_excel(writer, sheet_name='Cross Tabulation')
                        
                        # Apply header formatting
                        worksheet = writer.sheets['Cross Tabulation']
                        for col_num, value in enumerate([''] + list(ct.columns)):
                            worksheet.write(0, col_num, value, header_format)
                    except TypeError:
                        # Handle unhashable types like lists
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
        labels = request.form.getlist('field_labels[]')
        types = request.form.getlist('field_types[]')
        options_list = request.form.getlist('field_options[]')
        location_identifiers = request.form.getlist('location_field_identifier[]')
        required_fields = request.form.getlist('field_required[]')
        allow_other_fields = request.form.getlist('allow_other[]')
        if not title:
            flash('Form title is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
        if not labels:
            flash('At least one field is required.', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))
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
            fields.append(field)
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
            
        # First search patients table by patient_id, order by created_at desc for newest first
        response = supabase.table('patients').select('patient_id, data, created_at').like('patient_id', f"%{query}%").order('created_at', desc=True).limit(10).execute()
        
        # Add patient_id matches to results
        if response.data:
            for patient in response.data:
                patient_id = patient['patient_id']
                if patient_id not in seen_ids:
                    results.append(patient)
                    seen_ids.add(patient_id)
        
        # Simplify name search - Supabase can't easily do complex JSON searches via API
        # So we'll fetch records and filter in Python
        if len(results) < 10:
            try:
                # Get additional patients (up to 50) not already in results, newest first
                additional_patients = []
                if seen_ids:
                    additional_response = supabase.table('patients').select('patient_id, data, created_at').not_('patient_id', 'in', list(seen_ids)).order('created_at', desc=True).limit(50).execute()
                    additional_patients = additional_response.data
                else:
                    additional_response = supabase.table('patients').select('patient_id, data, created_at').order('created_at', desc=True).limit(50).execute()
                    additional_patients = additional_response.data
                
                # Common name field variations to check
                name_fields = ["Name", "Full Name", "First Name", "Last Name", "Patient Name"]
                query_lower = query.lower()
                
                # Manually search through JSON data for name matches
                for patient in additional_patients:
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
                
            except Exception as e:
                print(f"Error during manual name search: {str(e)}")
        
        # If we still have fewer than 5 results, try searching form submissions as a fallback
        if len(results) < 5:
            try:
                # Search in submissions by patient_id, order by newest first
                submissions_response = supabase.table('form_submissions').select('patient_id, data, created_at').like('patient_id', f"%{query}%").order('created_at', desc=True).limit(10).execute()
                
                # Process submission results
                if submissions_response.data:
                    for submission in submissions_response.data:
                        patient_id = submission['patient_id']
                        if patient_id not in seen_ids and len(results) < 10:
                            results.append({
                                'patient_id': patient_id,
                                'data': submission.get('data', {}),
                                'created_at': submission.get('created_at')
                            })
                            seen_ids.add(patient_id)
                
                # Also manually check names in submissions, order by newest first
                additional_submissions = supabase.table('form_submissions').select('patient_id, data, created_at').order('created_at', desc=True).limit(20).execute()
                
                if additional_submissions.data:
                    query_lower = query.lower()
                    for submission in additional_submissions.data:
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
            
            # Group form data by form ID
            for submission in submissions:
                form = submission.get('forms', {})
                form_id = form.get('id')
                if not form_id:
                    continue
                
                # Create form details entry if we haven't seen this form before
                if form_id not in result['form_details']:
                    result['form_details'][form_id] = {
                        'title': form.get('title', 'Unknown Form'),
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
        
        # Get form details for each form ID in the patient data
        form_ids = patient.get('data', {}).keys()
        for form_id in form_ids:
            form_response = supabase.table('forms').select('id, title, fields, project_id, projects(name)').eq('id', form_id).execute()
            
            if form_response.data:
                form = form_response.data[0]
                
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
        
        # Fetch submissions for this form
        submissions_response = supabase.table('form_submissions').select('data').eq('form_id', form_id).execute()
        
        if submissions_response.data:
            for submission in submissions_response.data:
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
    
    Returns:
        JSON: List of patient records with eligibility status
    """
    try:
        print(f"Fetching waitlist for form: {form_id}")
        
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
        all_forms_response = supabase.table('forms').select('*').eq('project_id', project['id']).order('created_at').execute()
        project_forms = all_forms_response.data
        
        # Map form IDs to their positions in the sequence
        form_indices = {f['id']: idx for idx, f in enumerate(project_forms)}
        current_form_index = form_indices.get(form_id, 0)
        
        # Get all patients
        patients_response = supabase.table('patients').select('*').execute()
        patients = patients_response.data
        
        # Get all submissions for tracking completed forms
        submissions_response = supabase.table('form_submissions').select('form_id, patient_id').execute()
        submissions = submissions_response.data
        
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
            
            # Try to get patient name from data
            if patient.get('data'):
                for form_data in patient['data'].values():
                    if isinstance(form_data, dict):
                        # Look for common name fields
                        for field in ['Full Name', 'Name', 'Patient Name', 'First Name']:
                            if field in form_data and form_data[field]:
                                patient_display_name = form_data[field]
                                break
                    if patient_display_name:
                        break
            
            result.append({
                'patient_id': patient_id,
                'display_name': patient_display_name,
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

# Correctly indented start of the main execution block
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Set debug=False for production
