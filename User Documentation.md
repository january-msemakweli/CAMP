# CAMP Healthcare Data Collection System - User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
   - [Registration and Login](#registration-and-login)
3. [For Regular Users](#for-regular-users)
   - [Dashboard Overview](#user-dashboard-overview)
   - [Viewing Available Forms](#viewing-available-forms)
   - [Patient Registration](#patient-registration)
   - [Submitting Forms](#submitting-forms)
   - [Viewing Dataset](#viewing-dataset)
4. [For Administrators](#for-administrators)
   - [Admin Dashboard](#admin-dashboard)
   - [User Management](#user-management)
   - [Programme Management](#programme-management)
   - [Form Creation and Management](#form-creation-and-management)
   - [Dataset Management](#dataset-management)
   - [Patient Management](#patient-management)
   - [Analytics](#analytics)
   - [Activity Logs](#activity-logs)
5. [Troubleshooting](#troubleshooting)

## Introduction

The CAMP Healthcare Data Collection System is designed to facilitate the collection, management, and analysis of patient data during healthcare programmes. The system allows for creating customized forms, managing patient records, and generating analytical insights from collected data.

## Getting Started

### Registration and Login

1. **Registration**: 
   - Navigate to the registration page by clicking "Register" on the landing page
   - Enter a username and password
   - Submit the form
   - Wait for an administrator to approve your account

2. **Login**:
   - Enter your username and password on the login page
   - If your account has been approved, you will be redirected to the appropriate dashboard
   - If not approved, you will see a message indicating pending approval

## For Regular Users

### User Dashboard Overview

After logging in, you will see your dashboard showing:
- Available programmes you have access to
- Forms you are permitted to fill out
- Recent activity

### Viewing Available Forms

1. Navigate to "My Forms" section on the dashboard
2. Click on any form to open it
3. Forms are organized by programme

### Patient Registration

Before filling out forms, you need to register a patient or search for an existing patient:

1. When opening a form, you'll see a patient ID field at the top
2. To register a new patient:
   - Click "Generate New Patient ID"
   - The system will automatically create a unique ID following the format DDMMYY-NNNN (date-sequential number)
3. To use an existing patient:
   - Start typing the patient ID in the search field
   - Select the correct patient from the dropdown list

### Submitting Forms

1. After selecting a patient, fill out all required fields in the form
2. Fields marked with an asterisk (*) are mandatory
3. Different field types include:
   - Text fields for free text
   - Dropdown menus for selecting from options
   - Radio buttons for single selections
   - Checkboxes for multiple selections
   - Date fields for selecting dates
4. Location fields (Region, District, Ward) are interdependent - select in order
5. Click "Submit" when the form is complete
6. You will see a confirmation message upon successful submission

### Viewing Dataset

Regular users can view dataset information:

1. Navigate to "Dataset" in the main menu
2. Select a programme to view its data
3. Use filters to narrow down the displayed data
4. Search functionality allows finding specific patients or data
5. Click on "Details" for any patient to view their complete record

## For Administrators

### Admin Dashboard

As an administrator, your dashboard provides an overview of:
- Pending user approvals
- Programme statistics
- Recent activity
- Quick access to all administrative functions

### User Management

Administrators can manage all users in the system:

1. **Approving New Users**:
   - From the admin dashboard, see "Pending Approvals" section
   - Review each user request
   - Click "Approve" to grant access or "Delete" to reject

2. **Creating Users**:
   - Click "Create New User" button
   - Fill in username and password
   - Check "Admin" checkbox to create an administrator account
   - All admin-created accounts are automatically approved

3. **Managing Existing Users**:
   - View all users in the user management section
   - Toggle admin status
   - Delete users as needed

### Programme Management

Programmes are the top-level organization for forms and data:

1. **Creating a New Programme**:
   - From the admin dashboard, click "Create New Programme"
   - Enter the programme name
   - Click "Create"

2. **Managing Programmes**:
   - View all programmes in the programmes section
   - Click on any programme to see its details
   - Delete programmes as needed (this will delete all associated forms and data)

3. **Programme Access**:
   - For each programme, you can grant access to specific users
   - In the programme details page, use the "Grant Access" section
   - Select a user from the dropdown and click "Grant Access"
   - Remove access using the "Revoke" button next to each user

### Form Creation and Management

Forms are the tools for data collection within programmes:

1. **Creating Forms**:
   - Navigate to a programme's detail page
   - Click "Create New Form"
   - Enter a form title
   - Add fields by clicking "Add Field"
   - For each field, specify:
     * Label (field name)
     * Type (text, number, dropdown, radio, checkbox, date)
     * Options (for dropdown, radio, and checkbox types)
     * Location field identifier (for Region, District, Ward fields)
   - Click "Create Form" to save

2. **Editing Forms**:
   - Open the form details page
   - Click "Edit Form"
   - Modify fields as needed
   - Save changes

3. **Managing Form Access**:
   - In the form details page, use the "Grant Access" section
   - Select a user and click "Grant Access"
   - Only users with access to the parent programme will be available
   - Remove access using the "Revoke" button

### Dataset Management

The dataset view allows comprehensive exploration of collected data:

1. **Viewing Dataset**:
   - Navigate to "Dataset" in the main menu
   - Select a programme to view its data
   - All patients and form submissions will be displayed in a table

2. **Filtering Data**:
   - Use the filter button to open filtering options
   - Filter by:
     * Programme
     * Form
     * Field value
     * Date range
   - Apply filters to narrow down displayed data

3. **Searching**:
   - Use the search box to find specific patients or data values
   - Search works across all fields

4. **Exporting Data**:
   - Click "Export Dataset" to download data as Excel file
   - The export respects current filters

### Patient Management

Administrators have special capabilities for patient management:

1. **Viewing Patient Details**:
   - In the dataset view, click "Details" on any patient record
   - A modal will display all information collected for the patient
   - Data is organized by the forms it was collected in

2. **Deleting Patients**:
   - In the patient details modal, administrators see a "Delete Patient" button
   - Clicking this button prompts for confirmation
   - Confirming will completely remove:
     * All form submissions for the patient
     * The patient record itself
   - This action cannot be undone

### Analytics

The analytics section provides data visualization and analysis:

1. **Accessing Analytics**:
   - Navigate to "Analytics" in the admin menu
   - Select a programme and form to analyze

2. **Analysis Types**:
   - **Summary Statistics**: View statistical measures for numeric fields
   - **Frequency Distribution**: See distribution of values in any field
   - **Cross-tabulation**: Examine relationships between two fields
   - **Time Series**: Analyze data changes over time
   - **Correlation Matrix**: Discover correlations between numeric fields
   - **Cohort Analysis**: Track groups over time

3. **Visualization**:
   - Each analysis type provides appropriate visualizations
   - Charts include histograms, bar charts, line graphs, heatmaps
   - Statistical tables accompany visualizations

4. **Exporting Analysis**:
   - Export analyses in Excel or CSV format
   - Charts can be copied or saved as images

### Activity Logs

Monitors all system activity for security and auditing:

1. **Viewing Logs**:
   - Navigate to "Activity Logs" in the admin menu
   - See all actions taken in the system

2. **Log Information**:
   - User who performed the action
   - Action type (create, update, delete, etc.)
   - Entity affected (patient, form, project, etc.)
   - Timestamp
   - IP address

3. **Clearing Logs**:
   - Use "Clear Logs" button to remove all logs
   - This action is logged itself for accountability

## Troubleshooting

### Common Issues

1. **Form Submission Errors**:
   - Ensure all required fields are completed
   - Check that dates are in the correct format
   - Verify the patient ID is valid

2. **Access Denied**:
   - Ensure your account has been approved
   - Check that you have been granted access to the specific programme or form
   - Contact an administrator if you believe you should have access

3. **Patient ID Search Issues**:
   - Ensure you're typing the ID in the correct format (DDMMYY-NNNN)
   - Patient IDs are case-sensitive
   - Try using partial search with just the numeric portion

4. **Data Not Appearing in Dataset**:
   - Verify your filters aren't excluding the data
   - Ensure forms were successfully submitted
   - Try clearing all filters and search terms

5. **Database Connection Issues**:
   - If you see database connection errors, notify your system administrator
   - The application may need to be restarted

For any persistent issues, please contact your system administrator.

---

This manual covers the core functionality of the CAMP Healthcare Data Collection System. As the system evolves, new features may be added and existing ones modified. 