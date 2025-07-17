#!/usr/bin/env python3
"""
Migration script to move existing "first form" registration data 
from form_submissions to the centralized patients table.

This script:
1. Identifies all "first forms" (registration forms) across all projects
2. Migrates their data to patients.data['registration'] field
3. Preserves existing data and handles conflicts
4. Provides dry-run mode for safety
"""

import json
import sys
from datetime import datetime
from supabase import create_client

# Import the configuration from your main app
try:
    from app import supabase, get_form_is_first
    print("✓ Successfully imported Supabase client and helper functions")
except ImportError as e:
    print(f"✗ Error importing from app.py: {e}")
    print("Please ensure this script is in the same directory as app.py")
    sys.exit(1)

def get_all_registration_forms():
    """Get all forms that are considered 'first forms' (registration forms)"""
    print("\n🔍 Identifying registration forms...")
    
    # Get all forms
    all_forms_response = supabase.table('forms').select('id, title, project_id, created_at').limit(10000).execute()
    if not all_forms_response.data:
        print("No forms found in database")
        return []
    
    registration_forms = []
    for form in all_forms_response.data:
        form_id = form.get('id')
        if form_id and get_form_is_first(form_id):
            registration_forms.append(form)
            print(f"  📋 Found registration form: {form.get('title')} (ID: {form_id})")
    
    print(f"✓ Identified {len(registration_forms)} registration forms")
    return registration_forms

def get_registration_submissions(form_ids):
    """Get all submissions for registration forms"""
    print(f"\n📊 Fetching submissions for {len(form_ids)} registration forms...")
    
    if not form_ids:
        return []
    
    # Fetch submissions for all registration forms
    submissions = []
    page_size = 1000
    start = 0
    
    while True:
        try:
            page_response = supabase.table('form_submissions')\
                .select('patient_id, form_id, data, created_at, forms(title, project_id)')\
                .in_('form_id', form_ids)\
                .range(start, start + page_size - 1)\
                .execute()
            
            page_data = page_response.data
            if not page_data:
                break
                
            submissions.extend(page_data)
            print(f"  📥 Fetched {len(page_data)} submissions (total: {len(submissions)})")
            
            if len(page_data) < page_size:
                break
                
            start += page_size
            
        except Exception as e:
            print(f"  ⚠️  Error fetching submissions page: {str(e)}")
            break
    
    print(f"✓ Total registration submissions found: {len(submissions)}")
    return submissions

def prepare_migration_data(submissions):
    """Prepare migration data by grouping submissions by patient"""
    print(f"\n🔄 Preparing migration data for {len(submissions)} submissions...")
    
    patient_registration_data = {}
    
    for submission in submissions:
        patient_id = submission['patient_id']
        form_data = submission.get('data', {})
        created_at = submission.get('created_at', '')
        form_info = submission.get('forms', {})
        form_title = form_info.get('title', 'Unknown')
        project_id = form_info.get('project_id', 'Unknown')
        
        if not form_data:
            continue
        
        if patient_id not in patient_registration_data:
            patient_registration_data[patient_id] = {
                'latest_data': {},
                'latest_timestamp': '',
                'sources': []
            }
        
        # Keep track of all sources for this patient's registration data
        patient_registration_data[patient_id]['sources'].append({
            'form_title': form_title,
            'project_id': project_id,
            'created_at': created_at,
            'field_count': len(form_data)
        })
        
        # Use the latest registration data
        if not patient_registration_data[patient_id]['latest_timestamp'] or \
           (created_at and created_at > patient_registration_data[patient_id]['latest_timestamp']):
            patient_registration_data[patient_id]['latest_data'] = form_data
            patient_registration_data[patient_id]['latest_timestamp'] = created_at
    
    print(f"✓ Prepared migration data for {len(patient_registration_data)} unique patients")
    
    # Show summary of patient sources
    for patient_id, data in list(patient_registration_data.items())[:5]:  # Show first 5 as examples
        sources_summary = "; ".join([f"{s['form_title']} ({len(s)} fields)" for s in data['sources'][:3]])
        if len(data['sources']) > 3:
            sources_summary += f" + {len(data['sources']) - 3} more"
        print(f"  👤 Patient {patient_id}: {sources_summary}")
    
    if len(patient_registration_data) > 5:
        print(f"  ... and {len(patient_registration_data) - 5} more patients")
    
    return patient_registration_data

def check_existing_patients(patient_ids):
    """Check which patients already exist in the patients table"""
    print(f"\n🔍 Checking existing patient records for {len(patient_ids)} patients...")
    
    existing_patients = {}
    batch_size = 1000
    
    for i in range(0, len(patient_ids), batch_size):
        batch = patient_ids[i:i + batch_size]
        try:
            response = supabase.table('patients')\
                .select('patient_id, data, created_at')\
                .in_('patient_id', batch)\
                .execute()
            
            for patient in response.data:
                existing_patients[patient['patient_id']] = patient
                
        except Exception as e:
            print(f"  ⚠️  Error checking batch: {str(e)}")
    
    print(f"✓ Found {len(existing_patients)} existing patient records")
    return existing_patients

def migrate_patient_data(patient_registration_data, existing_patients, dry_run=True):
    """Migrate registration data to patients table"""
    mode = "DRY RUN" if dry_run else "LIVE MIGRATION"
    print(f"\n🚀 Starting {mode}...")
    
    updates = []
    creates = []
    conflicts = []
    
    for patient_id, migration_data in patient_registration_data.items():
        registration_data = migration_data['latest_data']
        
        if patient_id in existing_patients:
            # Patient exists - check for conflicts
            existing_patient = existing_patients[patient_id]
            existing_data = existing_patient.get('data', {})
            existing_registration = existing_data.get('registration')
            
            if existing_registration:
                # Conflict: patient already has registration data
                conflicts.append({
                    'patient_id': patient_id,
                    'existing_fields': len(existing_registration),
                    'new_fields': len(registration_data),
                    'sources': migration_data['sources']
                })
            else:
                # Safe to add registration data
                new_data = existing_data.copy()
                new_data['registration'] = registration_data
                updates.append({
                    'patient_id': patient_id,
                    'new_data': new_data
                })
        else:
            # Patient doesn't exist - create new record
            creates.append({
                'patient_id': patient_id,
                'data': {'registration': registration_data}
            })
    
    print(f"\n📊 Migration Summary:")
    print(f"  ✅ Updates: {len(updates)} patients")
    print(f"  ➕ Creates: {len(creates)} patients")
    print(f"  ⚠️  Conflicts: {len(conflicts)} patients")
    
    # Show conflicts
    if conflicts:
        print(f"\n⚠️  Conflicts detected:")
        for conflict in conflicts[:5]:  # Show first 5
            sources = "; ".join([s['form_title'] for s in conflict['sources'][:2]])
            print(f"    👤 {conflict['patient_id']}: existing {conflict['existing_fields']} fields, new {conflict['new_fields']} fields from {sources}")
        if len(conflicts) > 5:
            print(f"    ... and {len(conflicts) - 5} more conflicts")
    
    if dry_run:
        print(f"\n🔍 DRY RUN COMPLETE - No changes made to database")
        return False
    
    # Perform actual migration
    print(f"\n🔄 Executing migration...")
    
    success_count = 0
    error_count = 0
    
    # Process updates
    for update in updates:
        try:
            supabase.table('patients')\
                .update({'data': update['new_data']})\
                .eq('patient_id', update['patient_id'])\
                .execute()
            success_count += 1
            if success_count % 100 == 0:
                print(f"  ✅ Updated {success_count}/{len(updates)} patients...")
        except Exception as e:
            print(f"  ❌ Error updating patient {update['patient_id']}: {str(e)}")
            error_count += 1
    
    # Process creates
    batch_size = 100
    for i in range(0, len(creates), batch_size):
        batch = creates[i:i + batch_size]
        try:
            supabase.table('patients').insert(batch).execute()
            success_count += len(batch)
            print(f"  ➕ Created batch of {len(batch)} patients...")
        except Exception as e:
            print(f"  ❌ Error creating patient batch: {str(e)}")
            error_count += len(batch)
    
    print(f"\n✅ Migration completed:")
    print(f"  ✅ Success: {success_count}")
    print(f"  ❌ Errors: {error_count}")
    print(f"  ⚠️  Conflicts skipped: {len(conflicts)}")
    
    return True

def main():
    """Main migration function"""
    print("🏥 Patient Registration Data Migration Tool")
    print("=" * 50)
    
    # Get command line argument for dry run
    dry_run = True
    if len(sys.argv) > 1 and sys.argv[1].lower() in ['--live', '--execute', '--run']:
        dry_run = False
        print("⚠️  LIVE MIGRATION MODE - Changes will be made to the database!")
        response = input("Are you sure you want to continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Migration cancelled.")
            return
    else:
        print("🔍 DRY RUN MODE - No changes will be made")
        print("Use --live flag to perform actual migration")
    
    try:
        # Step 1: Get all registration forms
        registration_forms = get_all_registration_forms()
        if not registration_forms:
            print("No registration forms found. Migration not needed.")
            return
        
        # Step 2: Get all registration submissions
        form_ids = [form['id'] for form in registration_forms]
        submissions = get_registration_submissions(form_ids)
        if not submissions:
            print("No registration submissions found. Migration not needed.")
            return
        
        # Step 3: Prepare migration data
        patient_registration_data = prepare_migration_data(submissions)
        if not patient_registration_data:
            print("No patient data to migrate.")
            return
        
        # Step 4: Check existing patients
        patient_ids = list(patient_registration_data.keys())
        existing_patients = check_existing_patients(patient_ids)
        
        # Step 5: Migrate data
        migrate_patient_data(patient_registration_data, existing_patients, dry_run)
        
        if dry_run:
            print(f"\n💡 To perform the actual migration, run:")
            print(f"   python {sys.argv[0]} --live")
        else:
            print(f"\n🎉 Migration completed successfully!")
            print(f"Registration data is now centralized in the patients table.")
    
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 