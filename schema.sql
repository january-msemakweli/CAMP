-- First drop all existing tables and relations
DROP TABLE IF EXISTS public.form_submissions CASCADE;
DROP TABLE IF EXISTS public.form_permissions CASCADE;
DROP TABLE IF EXISTS public.user_project_access CASCADE;
DROP TABLE IF EXISTS public.log_activities CASCADE;
DROP TABLE IF EXISTS public.forms CASCADE;
DROP TABLE IF EXISTS public.patients CASCADE;
DROP TABLE IF EXISTS public.projects CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;

-- Create users table
CREATE TABLE IF NOT EXISTS public.users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create projects table
CREATE TABLE IF NOT EXISTS public.projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create forms table
CREATE TABLE IF NOT EXISTS public.forms (
    id TEXT PRIMARY KEY,
    project_id TEXT, -- Constraint added separately below
    title TEXT NOT NULL,
    fields JSONB NOT NULL,
    is_archived BOOLEAN DEFAULT FALSE, -- Added for soft deletes
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create patients table (NEW - Project Agnostic)
CREATE TABLE IF NOT EXISTS public.patients (
    patient_id TEXT PRIMARY KEY,
    -- project_id TEXT, -- Removed: Patient record is now project-agnostic
    data JSONB, -- Stores all form data keyed by form_id
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create log_activities table
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

-- Create user_project_access table (NEW)
CREATE TABLE IF NOT EXISTS public.user_project_access (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL, -- Constraint added separately below (references users)
    project_id TEXT NOT NULL, -- Constraint added separately below (references projects)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, project_id) -- Ensure a user can only be granted access once per project
);

-- Create form_submissions table
CREATE TABLE IF NOT EXISTS public.form_submissions (
    id TEXT PRIMARY KEY,
    form_id TEXT NOT NULL,
    patient_id TEXT NOT NULL,
    submitted_by TEXT NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create form_permissions table
CREATE TABLE IF NOT EXISTS public.form_permissions (
    id TEXT PRIMARY KEY,
    form_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (form_id, user_id) -- Ensure a user can only be granted access once per form
);

-- Add ON DELETE clauses to foreign key constraints

-- Drop existing constraints first to modify them
ALTER TABLE public.forms DROP CONSTRAINT IF EXISTS forms_project_id_fkey;
ALTER TABLE public.log_activities DROP CONSTRAINT IF EXISTS log_activities_user_id_fkey;
ALTER TABLE public.user_project_access DROP CONSTRAINT IF EXISTS user_project_access_user_id_fkey;
ALTER TABLE public.user_project_access DROP CONSTRAINT IF EXISTS user_project_access_project_id_fkey;
ALTER TABLE public.form_submissions DROP CONSTRAINT IF EXISTS form_submissions_form_id_fkey;
ALTER TABLE public.form_submissions DROP CONSTRAINT IF EXISTS form_submissions_submitted_by_fkey;
ALTER TABLE public.form_permissions DROP CONSTRAINT IF EXISTS form_permissions_form_id_fkey;
ALTER TABLE public.form_permissions DROP CONSTRAINT IF EXISTS form_permissions_user_id_fkey;

-- Re-add constraints with desired ON DELETE behavior

-- Forms -> Projects: Delete forms if project is deleted (matches app logic)
ALTER TABLE public.forms
ADD CONSTRAINT forms_project_id_fkey
FOREIGN KEY (project_id) REFERENCES public.projects (id)
ON DELETE CASCADE;

-- Log Activities -> Users: Keep logs, set user_id to NULL if user deleted
ALTER TABLE public.log_activities
ADD CONSTRAINT log_activities_user_id_fkey
FOREIGN KEY (user_id) REFERENCES public.users (id)
ON DELETE SET NULL;

-- User Project Access -> Users: Delete access record if user deleted
ALTER TABLE public.user_project_access
ADD CONSTRAINT user_project_access_user_id_fkey
FOREIGN KEY (user_id) REFERENCES public.users (id)
ON DELETE CASCADE;

-- User Project Access -> Projects: Delete access record if project deleted
ALTER TABLE public.user_project_access
ADD CONSTRAINT user_project_access_project_id_fkey
FOREIGN KEY (project_id) REFERENCES public.projects (id)
ON DELETE CASCADE;

-- Form Submissions -> Forms: Delete submissions if form is deleted
ALTER TABLE public.form_submissions
ADD CONSTRAINT form_submissions_form_id_fkey
FOREIGN KEY (form_id) REFERENCES public.forms (id)
ON DELETE CASCADE;

-- Form Submissions -> Users: Keep submissions even if user is deleted
ALTER TABLE public.form_submissions
ADD CONSTRAINT form_submissions_submitted_by_fkey
FOREIGN KEY (submitted_by) REFERENCES public.users (id)
ON DELETE SET NULL;

-- Form Permissions -> Forms: Delete permissions if form is deleted
ALTER TABLE public.form_permissions
ADD CONSTRAINT form_permissions_form_id_fkey
FOREIGN KEY (form_id) REFERENCES public.forms (id)
ON DELETE CASCADE;

-- Form Permissions -> Users: Delete permissions if user is deleted
ALTER TABLE public.form_permissions
ADD CONSTRAINT form_permissions_user_id_fkey
FOREIGN KEY (user_id) REFERENCES public.users (id)
ON DELETE CASCADE;