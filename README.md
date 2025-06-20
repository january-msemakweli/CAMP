# MoAfyaCamps

A centralized platform for efficient health camp data collection and management.

## Features

- User registration and approval system
- Project and form management
- Real-time data collection
- Role-based access control (Admin/User)
- Supabase integration for data storage
- Responsive and modern UI

## Prerequisites

- Python 3.8 or higher
- Supabase account and project
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/MoAfyaCamps.git
cd MoAfyaCamps
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
SUPABASE_URL=your-supabase-url-here
SUPABASE_KEY=your-supabase-key-here
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Running the Application

1. Start the Flask development server:
```bash
flask run
```

2. Access the application at `http://localhost:5000`

## Default Admin Credentials

- Username: admin
- Password: moafya123

## Usage

### Admin Features
- Approve/delete user registrations
- Create and manage projects
- Create and manage forms
- View and export data

### User Features
- Register and wait for approval
- View available projects
- Submit data through forms
- View submitted data

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Waitlist Feature Implementation

### API Endpoint to Add in app.py

Add the following route to implement the waitlist functionality:

```python
@app.route('/api/form_waitlist/<form_id>', methods=['GET'])
def form_waitlist(form_id):
    """API endpoint to get the waitlist for a specific form.
    
    This endpoint returns patients who:
    1. Have not yet completed the current form
    2. For forms beyond the first, have completed the previous form
    
    Returns:
        JSON: List of patient records with eligibility status
    """
    try:
        # Get the form details
        form = db.session.query(Form).filter_by(id=form_id).first()
        if not form:
            return jsonify({'error': 'Form not found'}), 404
            
        # Get the project
        project = db.session.query(Project).filter_by(id=form.project_id).first()
        if not project:
            return jsonify({'error': 'Project not found'}), 404
            
        # Get all forms in this project to determine order
        project_forms = db.session.query(Form).filter_by(project_id=project.id).order_by(Form.form_index).all()
        form_indices = {f.id: idx for idx, f in enumerate(project_forms)}
        current_form_index = form_indices.get(form_id, 0)
        
        # Get all patients
        patients = db.session.query(Patient).all()
        result = []
        
        for patient in patients:
            # Skip patients who already have completed this form
            if patient.data and form_id in patient.data:
                continue
            
            # For forms beyond the first, check if the patient completed the previous form
            is_eligible = True
            patient_display_name = None
            last_completed_form = None
            
            if current_form_index > 0 and project_forms:
                # Find the previous form
                prev_form_id = project_forms[current_form_index - 1].id if current_form_index - 1 < len(project_forms) else None
                
                if prev_form_id and (not patient.data or prev_form_id not in patient.data):
                    is_eligible = False
                
                # Find the last completed form for this patient
                if patient.data:
                    for form_id in patient.data:
                        form_name = next((f.title for f in project_forms if f.id == form_id), None)
                        if form_name:
                            last_completed_form = form_name
                        
                        # Try to get patient name from registration form data
                        if not patient_display_name:
                            form_data = patient.data.get(form_id, {})
                            if isinstance(form_data, dict):
                                # Look for common name fields (adjust based on your form fields)
                                for field in ['Full Name', 'Name', 'Patient Name', 'First Name']:
                                    if field in form_data and form_data[field]:
                                        patient_display_name = form_data[field]
                                        break
            
            result.append({
                'patient_id': patient.patient_id,
                'display_name': patient_display_name,
                'last_form_completed': last_completed_form,
                'is_eligible': is_eligible
            })
        
        return jsonify({'patients': result})
    except Exception as e:
        app.logger.error(f"Error in form_waitlist: {str(e)}")
        return jsonify({'error': str(e)}), 500
```

### Implementation Notes:
1. This endpoint retrieves a list of patients who haven't completed the current form yet.
2. For forms beyond the first form in the sequence, it only shows patients as eligible if they've completed the previous form.
3. It provides extra information such as the patient's name (if available) and the last form they completed.
4. The front-end implementation in view_form.html will display this data in a table and allow users to select patients from the waitlist.

### Required Modifications:
- Ensure the Form model has a `form_index` field to determine the sequence of forms within a project.
- Update the form creation process to assign the correct form_index value.
- If the form_index is not available, you may need to modify the query to determine form order based on creation date or other criteria.

### Additional Considerations:
- You might want to add additional filters for the waitlist, such as filtering by location or other criteria.
- Consider adding pagination if the waitlist becomes very large.
- You could extend this feature to show when the patient completed previous forms.

### Update to view_form Route

You also need to update the existing `view_form` route in app.py to include the form_index information:

```python
@app.route('/view_form/<form_id>')
@login_required
def view_form(form_id):
    # Existing code to fetch the form
    form = db.session.query(Form).filter_by(id=form_id).first()
    if not form:
        flash('Form not found.', 'danger')
        return redirect(url_for('index'))
    
    # Get the project
    project = db.session.query(Project).filter_by(id=form.project_id).first()
    
    # Get all forms in this project to determine form index
    project_forms = db.session.query(Form).filter_by(project_id=project.id).order_by(Form.form_index).all()
    form_indices = {f.id: idx for idx, f in enumerate(project_forms)}
    form.form_index = form_indices.get(form_id, 0)  # Add form_index to form object
    
    # Is this the first form in the project?
    is_first_form = form.form_index == 0
    
    # Rest of your existing view_form function
    # ...
    
    return render_template('view_form.html', 
                          form=form, 
                          project=project, 
                          is_first_form=is_first_form,
                          # Rest of your template variables
                          ) 