-- 1. Table: admin_users
CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'admin' CHECK (role = 'admin'),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

-- 2. Table: personal_profiles
CREATE TABLE personal_profiles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    photo_url TEXT NOT NULL,
    photo_file_id TEXT NOT NULL,
    likes JSONB DEFAULT '[]'::jsonb,
    hobbies JSONB DEFAULT '[]'::jsonb,
    description_html TEXT NOT NULL,
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- 3. Table: stories
CREATE TABLE stories (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    thumbnail_url TEXT NOT NULL,
    thumbnail_file_id TEXT NOT NULL,
    event_date DATE NOT NULL,
    short_description TEXT NOT NULL,
    content_html TEXT NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('draft', 'published')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_stories_slug ON stories(slug);
CREATE INDEX idx_stories_status_deleted ON stories(status, deleted_at);
CREATE INDEX idx_stories_event_date ON stories(event_date DESC);

-- [BARU] 10. Table: story_gallery_images
-- Menyimpan banyak gambar opsional untuk satu story
CREATE TABLE story_gallery_images (
    id SERIAL PRIMARY KEY,
    story_id INTEGER NOT NULL REFERENCES stories(id) ON DELETE CASCADE,
    image_url TEXT NOT NULL,
    image_file_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_story_gallery_story_id ON story_gallery_images(story_id);

-- 4. Table: moments
CREATE TABLE moments (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    event_date DATE NOT NULL,
    image_url TEXT NOT NULL,
    image_file_id TEXT NOT NULL,
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_moments_event_date ON moments(event_date DESC);

-- 5. Table: gallery_items
CREATE TABLE gallery_items (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    event_date DATE NOT NULL,
    image_url TEXT NOT NULL,
    image_file_id TEXT,
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN ('upload', 'external_url')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_gallery_event_date ON gallery_items(event_date DESC);

-- 6. Table: gallery_videos
CREATE TABLE gallery_videos (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    event_date DATE NOT NULL,
    video_url TEXT NOT NULL,
    youtube_video_id VARCHAR(100),
    thumbnail_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_videos_event_date ON gallery_videos(event_date DESC);

-- 7. Table: letters
CREATE TABLE letters (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    event_date DATE NOT NULL,
    description_html TEXT NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('draft', 'published')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_letters_status_deleted ON letters(status, deleted_at);

-- 8. Table: songs
CREATE TABLE songs (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    mp3_url TEXT NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('active', 'nonactive')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX idx_one_active_song ON songs(status) WHERE status = 'active' AND deleted_at IS NULL;

-- 9. Table: site_settings
CREATE TABLE site_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO site_settings (setting_key, setting_value) 
VALUES ('relationship_start_date', '2026-10-25T00:00:00+08:00')
ON CONFLICT (setting_key) DO NOTHING;