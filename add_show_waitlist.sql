-- Migration script to add show_waitlist column to forms table
-- Run this SQL script directly on your database if the Python migration script fails

-- Add column if it doesn't exist
ALTER TABLE public.forms 
ADD COLUMN IF NOT EXISTS show_waitlist BOOLEAN DEFAULT FALSE;

-- Set all existing forms to have show_waitlist = FALSE
UPDATE public.forms 
SET show_waitlist = FALSE 
WHERE show_waitlist IS NULL;

-- Add commentary
COMMENT ON COLUMN public.forms.show_waitlist IS 'Controls whether the waitlist is visible to users with form access';

-- Verify the column exists
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'forms' AND column_name = 'show_waitlist';

-- Display forms with waitlist enabled (should be none initially)
SELECT id, title, show_waitlist 
FROM public.forms
ORDER BY title; 