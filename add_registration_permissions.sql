-- Migration script to add registration_permissions table
-- Run this SQL script directly on your database if needed

-- Create registration_permissions table if it doesn't exist
CREATE TABLE IF NOT EXISTS public.registration_permissions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id) -- Ensure a user can only be granted registration access once
);

-- Add foreign key constraint if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'registration_permissions_user_id_fkey'
    ) THEN
        ALTER TABLE public.registration_permissions
        ADD CONSTRAINT registration_permissions_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users (id)
        ON DELETE CASCADE;
    END IF;
END $$;

-- Add commentary
COMMENT ON TABLE public.registration_permissions IS 'Controls which users can access the patient registration system';
COMMENT ON COLUMN public.registration_permissions.user_id IS 'Reference to users table - which user has registration access';

-- Verify the table exists
SELECT 
    table_name, 
    column_name, 
    data_type, 
    is_nullable 
FROM information_schema.columns 
WHERE table_name = 'registration_permissions' 
ORDER BY ordinal_position;

-- Display current registration permissions (should be none initially)
SELECT 
    rp.id,
    u.username,
    rp.created_at
FROM public.registration_permissions rp
JOIN public.users u ON rp.user_id = u.id
ORDER BY rp.created_at DESC; 