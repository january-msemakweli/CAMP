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
    """Check for admin user but don't create tables"""
    try:
        print("Checking for admin user...")
        
        # Check if admin user exists
        response = supabase.table('users').select('*').eq('username', 'admin').execute()
        if not response.data:
            print("Admin user not found, but automatic creation is disabled.")
            print("Please run the database setup scripts to create the admin user.")
        else:
            print("Admin user exists")
    except Exception as e:
        print(f"Error checking admin user: {str(e)}")
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
    if all_forms_response.data and len(all_forms_response.data) > 0:
        # Check if current form is the first one created
        is_first_form = all_forms_response.data[0]['id'] == form_id
    
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
    
    return render_template('view_form.html', 
                          form=form, 
                          project=project, 
                          submissions=submissions, 
                          users=project_users,  # Now only showing users with project access
                          user_permissions=user_permissions,
                          is_first_form=is_first_form)

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
    
    # Collect form data
    form_data = {}
    for field in form['fields']:
        field_label = field['label']
        if field['type'] in ['dropdown', 'radio']:
            form_data[field_label] = request.form.get(field_label)
        elif field['type'] == 'checkbox':
            form_data[field_label] = request.form.getlist(field_label)
        else:
            form_data[field_label] = request.form.get(field_label)
    
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
    
    # Get the selected project name if a project is selected
    selected_project_name = None
    if project_id:
        project_response = supabase.table('projects').select('name').eq('id', project_id).execute()
        if project_response.data:
            selected_project_name = project_response.data[0]['name']

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

    # 11. Convert patient_data dictionary to patient_data_list for the template
    patient_data_list = []
    for patient_id, data in patient_data.items():
        # Create a flattened representation with patient_id and all field values
        patient_row = {'patient_id': patient_id}
        
        # Add all field values from merged_data using the original field labels
        if 'merged_data' in data:
            for normalized_key, value in data['merged_data'].items():
                if normalized_key in field_label_map:
                    original_key = field_label_map[normalized_key]
                    patient_row[original_key] = value
        
        patient_data_list.append(patient_row)

    return render_template('dataset_view.html',
                         patient_data=patient_data,
                         patient_data_list=patient_data_list,  # Add this new parameter
                         # Pass the final ordered list of field labels
                         ordered_fields=final_ordered_fields, 
                         all_fields_for_filter=final_ordered_fields,  # Add this missing parameter
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
    
    # Get all ordered forms to build field ordering
    # Similar to dataset_view, build ordered_fields list based on form definitions
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

    # Build ordered_fields list based on form definitions - similar to dataset_view
    ordered_fields = []
    seen_normalized_fields = set()
    field_label_map = {}

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
    
    # Group submissions by patient_id
    patient_data = {}
    all_data_fields_normalized = set()

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

    # Identify Extra Fields (present in data but not in form definitions)
    extra_normalized_fields = all_data_fields_normalized - seen_normalized_fields
    extra_field_labels = sorted([field_label_map[norm_key] for norm_key in extra_normalized_fields if norm_key in field_label_map])
    
    # Combine ordered fields with extra fields - matches dataset_view
    final_ordered_fields = ordered_fields + extra_field_labels
    
    # Pre-process patient data to merge values
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
    
    # Create DataFrame
    data = []
    for patient_id, data_dict in patient_data.items():
        row = {'Patient ID': patient_id}
        if 'merged_data' in data_dict:
            for field_label in final_ordered_fields:
                normalized_key = field_label.lower().strip().replace(' ', '_')
                if normalized_key in data_dict['merged_data']:
                    row[field_label] = data_dict['merged_data'][normalized_key]
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
            
        # Search patients table
        response = supabase.table('patients').select('patient_id, data').like('patient_id', f"%{query}%").limit(10).execute()
        
        if not response.data:
            # No direct matches, try using form submissions for backup
            # This handles the case where old data might not be in the patients table
            submissions_response = supabase.table('form_submissions').select('patient_id').like('patient_id', f"%{query}%").limit(10).execute()
            
            # Format the results as expected
            results = []
            seen_ids = set()  # To prevent duplicates
            
            for submission in submissions_response.data:
                patient_id = submission['patient_id']
                if patient_id not in seen_ids:
                    results.append({
                        'patient_id': patient_id,
                        'data': {}  # No associated data for these legacy records
                    })
                    seen_ids.add(patient_id)
            
            return jsonify(results)
        
        # Return the results
        return jsonify(response.data)
    
    except Exception as e:
        print(f"Error searching for patient ID: {str(e)}")
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

# Correctly indented start of the main execution block
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) # Set debug=False for production
