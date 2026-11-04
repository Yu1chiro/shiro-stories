require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const ImageKit = require('imagekit');
const sharp = require('sharp');
const sanitizeHtml = require('sanitize-html');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. CONFIGURATION & INITIALIZATION
// ==========================================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const imagekit = new ImageKit({
    publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
    privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
    urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT
});

// Limit ditingkatkan menjadi 50mb untuk mengakomodasi upload multi-gambar gallery stories
app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.disable('x-powered-by'); 

const pinLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { success: false, message: 'Too many PIN attempts. Please try again later.' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: 'Too many login attempts. Please try again later.' } });

const sanitizeOptions = {
    allowedTags: [ 'h1', 'h2', 'h3', 'p', 'br', 'b', 'i', 'em', 'strong', 'u', 's', 'ul', 'ol', 'li', 'blockquote', 'a', 'img' ],
    allowedAttributes: { 'a': ['href', 'target', 'rel'], 'img': ['src', 'alt', 'width', 'height'], 'p': ['class'], 'h1': ['class'], 'h2': ['class'], 'h3': ['class'] },
    allowedClasses: { '*': ['ql-align-center', 'ql-align-right', 'ql-align-justify'] },
    allowedSchemes: ['http', 'https']
};

// ==========================================
// 2. MIDDLEWARES
// ==========================================
const requirePublicAuth = (req, res, next) => {
    const token = req.cookies.scrapbook_access;
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized. Please enter PIN.' });
    try { jwt.verify(token, process.env.JWT_ACCESS_SECRET); next(); } 
    catch (err) { return res.status(401).json({ success: false, message: 'Invalid or expired session.' }); }
};

const requireAdminAuth = async (req, res, next) => {
    const token = req.cookies.scrapbook_admin;
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized admin access.' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_ADMIN_SECRET);
        const result = await pool.query('SELECT role FROM admin_users WHERE id = $1', [decoded.id]);
        if (result.rows.length === 0 || result.rows[0].role !== 'admin') throw new Error('Admin not found or invalid role');
        req.admin = decoded; next();
    } catch (err) { return res.status(401).json({ success: false, message: 'Invalid admin session.' }); }
};

// ==========================================
// 3. STATIC HTML ROUTING
// ==========================================
const serveHtml = (folder, filename, req, res) => {
    const filePath = path.join(__dirname, folder, filename);
    if (fs.existsSync(filePath)) res.sendFile(filePath); else res.status(404).send('Page not found');
};

app.get('/', (req, res) => serveHtml('public', 'index.html', req, res));
app.get('/index.html', (req, res) => res.redirect('/'));
app.get('/read-stories', (req, res) => serveHtml('public', 'read-stories.html', req, res));
app.get('/signin', (req, res) => serveHtml('public', 'signin.html', req, res));

app.get('/admin/*', (req, res, next) => {
    const token = req.cookies.scrapbook_admin;
    if (!token) return res.redirect('/signin');
    try { jwt.verify(token, process.env.JWT_ADMIN_SECRET); next(); } 
    catch (err) { return res.redirect('/signin'); }
});

app.get('/admin/dashboard', (req, res) => serveHtml('admin', 'dashboard.html', req, res));
app.get('/admin/create-stories', (req, res) => serveHtml('admin', 'create-stories.html', req, res));
app.get('/admin/create-personal-profile', (req, res) => serveHtml('admin', 'create-personal-profile.html', req, res));
app.get('/admin/create-gallery', (req, res) => serveHtml('admin', 'create-gallery.html', req, res));
app.get('/admin/create-moments', (req, res) => serveHtml('admin', 'create-moments.html', req, res));
app.get('/admin/gallery-video', (req, res) => serveHtml('admin', 'gallery-video.html', req, res));
app.get('/admin/create-song', (req, res) => serveHtml('admin', 'create-song.html', req, res));
app.get('/admin/create-letters', (req, res) => serveHtml('admin', 'create-letters.html', req, res));

// ==========================================
// 4. AUTHENTICATION APIs
// ==========================================
app.post('/api/access/verify-pin', pinLimiter, (req, res) => {
    const { pin } = req.body;
    if (pin === process.env.SCRAPBOOK_PIN) {
        const token = jwt.sign({ access: 'granted' }, process.env.JWT_ACCESS_SECRET, { expiresIn: '7d' });
        res.cookie('scrapbook_access', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
        return res.json({ success: true, message: 'Access granted' });
    }
    res.status(401).json({ success: false, message: 'Invalid PIN' });
});

app.get('/api/access/status', (req, res) => {
    const token = req.cookies.scrapbook_access;
    if (!token) return res.json({ success: false });
    try { jwt.verify(token, process.env.JWT_ACCESS_SECRET); res.json({ success: true }); } 
    catch (err) { res.json({ success: false }); }
});

app.post('/api/access/logout', (req, res) => {
    res.clearCookie('scrapbook_access'); res.json({ success: true, message: 'Logged out' });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT id, username, password_hash, role FROM admin_users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (user && await bcrypt.compare(password, user.password_hash)) {
            const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_ADMIN_SECRET, { expiresIn: '24h' });
            await pool.query('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
            res.cookie('scrapbook_admin', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'Strict', maxAge: 24 * 60 * 60 * 1000 });
            return res.json({ success: true, message: 'Login successful' });
        }
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    } catch (err) { res.status(500).json({ success: false, message: 'Server error' }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('scrapbook_admin'); res.json({ success: true, message: 'Admin logged out' }); });
app.get('/api/auth/me', requireAdminAuth, (req, res) => { res.json({ success: true, user: req.admin }); });

// ==========================================
// 5. HELPER FUNCTIONS
// ==========================================
const uploadToImageKit = async (base64Image, folder) => {
    const matches = base64Image.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) throw new Error('Invalid base64 string');
    const imageBuffer = Buffer.from(matches[2], 'base64');
    const webpBuffer = await sharp(imageBuffer).webp({ quality: 80 }).toBuffer();
    const uploadResult = await imagekit.upload({ file: webpBuffer, fileName: `img_${Date.now()}.webp`, folder: `/scrapbook/${folder}` });
    return { url: uploadResult.url, fileId: uploadResult.fileId };
};

const deleteFromImageKit = async (fileId) => {
    if(!fileId) return;
    try { await imagekit.deleteFile(fileId); } catch (error) { console.error(`Failed to delete ImageKit file ${fileId}:`, error); }
};

const getPagination = (req) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 4;
    return { limit, offset: (page - 1) * limit, page };
};

// ==========================================
// 6. PUBLIC API (Requires PIN)
// ==========================================
app.get('/api/public/profiles', requirePublicAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT name, photo_url, likes, hobbies, description_html FROM personal_profiles WHERE deleted_at IS NULL ORDER BY display_order ASC LIMIT 2');
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/stories', requirePublicAuth, async (req, res) => {
    const { limit, offset } = getPagination(req);
    try {
        const result = await pool.query(
            'SELECT title, slug, thumbnail_url, event_date, short_description FROM stories WHERE status = $1 AND deleted_at IS NULL ORDER BY event_date DESC LIMIT $2 OFFSET $3',
            ['published', limit, offset]
        );
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/stories/:slug', requirePublicAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, title, thumbnail_url, event_date, content_html FROM stories WHERE slug = $1 AND status = $2 AND deleted_at IS NULL',
            [req.params.slug, 'published']
        );
        if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Story not found' });
        
        const storyData = result.rows[0];
        
        // [BARU] Fetch opsi gallery images untuk cerita ini
        const galleryRes = await pool.query('SELECT id, image_url FROM story_gallery_images WHERE story_id = $1 ORDER BY id ASC', [storyData.id]);
        storyData.gallery = galleryRes.rows;

        res.json({ success: true, data: storyData });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/moments', requirePublicAuth, async (req, res) => {
    const { limit, offset } = getPagination(req);
    try {
        const result = await pool.query('SELECT title, image_url, event_date FROM moments WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/gallery', requirePublicAuth, async (req, res) => {
    const { limit, offset } = getPagination(req);
    try {
        const result = await pool.query('SELECT title, image_url, event_date FROM gallery_items WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/videos', requirePublicAuth, async (req, res) => {
    const { limit, offset } = getPagination(req);
    try {
        // Tambahkan youtube_video_id pada statement SELECT di bawah ini
        const result = await pool.query('SELECT title, video_url, thumbnail_url, event_date, youtube_video_id FROM gallery_videos WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/letters', requirePublicAuth, async (req, res) => {
    const { limit, offset } = getPagination(req);
    try {
        const result = await pool.query('SELECT title, description_html, event_date FROM letters WHERE status = $1 AND deleted_at IS NULL ORDER BY event_date DESC LIMIT $2 OFFSET $3', ['published', limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/public/songs/active', requirePublicAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT title, mp3_url FROM songs WHERE status = $1 AND deleted_at IS NULL LIMIT 1', ['active']);
        res.json({ success: true, data: result.rows[0] || null });
    } catch (err) { res.status(500).json({ success: false }); }
});

// ==========================================
// 7. ADMIN API (Requires Admin Token)
// ==========================================

app.post('/api/admin/uploads/image', requireAdminAuth, async (req, res) => {
    try {
        const { image, folder = 'stories-content' } = req.body;
        if (!image) return res.status(400).json({ success: false, message: 'Image data missing' });
        const upload = await uploadToImageKit(image, folder);
        res.json({ success: true, url: upload.url, fileId: upload.fileId });
    } catch (err) { res.status(500).json({ success: false, message: 'Upload failed' }); }
});

app.get('/api/admin/dashboard/stats', requireAdminAuth, async (req, res) => {
    try {
        const queries = [
            pool.query('SELECT count(*) FROM stories WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM personal_profiles WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM moments WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM gallery_items WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM gallery_videos WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM letters WHERE deleted_at IS NULL'),
            pool.query('SELECT count(*) FROM songs WHERE deleted_at IS NULL')
        ];
        const results = await Promise.all(queries);
        res.json({ success: true, data: {
            stories: parseInt(results[0].rows[0].count), profiles: parseInt(results[1].rows[0].count),
            moments: parseInt(results[2].rows[0].count), gallery: parseInt(results[3].rows[0].count),
            videos: parseInt(results[4].rows[0].count), letters: parseInt(results[5].rows[0].count),
            songs: parseInt(results[6].rows[0].count)
        }});
    } catch (err) { res.status(500).json({ success: false, message: 'Failed to load stats' }); }
});

// Admin CRUD: STORIES [DIPERBARUI UNTUK GALLERY]
app.get('/api/admin/stories', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, slug, thumbnail_url, event_date, status FROM stories WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/stories/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM stories WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        if(result.rows.length === 0) return res.status(404).json({ success: false, message: 'Story not found' });
        
        const storyData = result.rows[0];
        const galleryRes = await pool.query('SELECT id, image_url FROM story_gallery_images WHERE story_id = $1 ORDER BY id ASC', [storyData.id]);
        storyData.gallery = galleryRes.rows;

        res.json({ success: true, data: storyData });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/stories', requireAdminAuth, async (req, res) => {
    const client = await pool.connect();
    try {
        const { title, slug, imageBase64, event_date, short_description, content_html, status, newGalleryImages } = req.body;
        const cleanHtml = sanitizeHtml(content_html, sanitizeOptions);
        
        await client.query('BEGIN');
        
        // Upload Thumbnail
        let thumbnailUrl = '', thumbnailFileId = '';
        if (imageBase64) {
            const upload = await uploadToImageKit(imageBase64, 'stories');
            thumbnailUrl = upload.url; thumbnailFileId = upload.fileId;
        }

        // Insert Story
        const insertRes = await client.query(
            'INSERT INTO stories (title, slug, thumbnail_url, thumbnail_file_id, event_date, short_description, content_html, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id',
            [title, slug, thumbnailUrl, thumbnailFileId, event_date, short_description, cleanHtml, status]
        );
        const storyId = insertRes.rows[0].id;

        // Upload & Insert Optional Gallery Images
        if (newGalleryImages && newGalleryImages.length > 0) {
            for (const base64Img of newGalleryImages) {
                const gUpload = await uploadToImageKit(base64Img, 'stories-gallery');
                await client.query(
                    'INSERT INTO story_gallery_images (story_id, image_url, image_file_id) VALUES ($1, $2, $3)',
                    [storyId, gUpload.url, gUpload.fileId]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'Story created' });
    } catch (err) { 
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, message: err.message }); 
    } finally {
        client.release();
    }
});

app.put('/api/admin/stories/:id', requireAdminAuth, async (req, res) => {
    const client = await pool.connect();
    try {
        const { id } = req.params;
        const { title, slug, imageBase64, event_date, short_description, content_html, status, newGalleryImages, deletedGalleryIds } = req.body;
        const cleanHtml = sanitizeHtml(content_html, sanitizeOptions);

        await client.query('BEGIN');

        // Update Thumbnail if changed
        if (imageBase64) {
            const oldRecord = await client.query('SELECT thumbnail_file_id FROM stories WHERE id = $1', [id]);
            const upload = await uploadToImageKit(imageBase64, 'stories');
            await client.query(
                'UPDATE stories SET title=$1, slug=$2, thumbnail_url=$3, thumbnail_file_id=$4, event_date=$5, short_description=$6, content_html=$7, status=$8, updated_at=CURRENT_TIMESTAMP WHERE id=$9',
                [title, slug, upload.url, upload.fileId, event_date, short_description, cleanHtml, status, id]
            );
            if(oldRecord.rows[0].thumbnail_file_id) await deleteFromImageKit(oldRecord.rows[0].thumbnail_file_id);
        } else {
            await client.query(
                'UPDATE stories SET title=$1, slug=$2, event_date=$3, short_description=$4, content_html=$5, status=$6, updated_at=CURRENT_TIMESTAMP WHERE id=$7',
                [title, slug, event_date, short_description, cleanHtml, status, id]
            );
        }

        // Process Deleted Gallery Images
        if (deletedGalleryIds && deletedGalleryIds.length > 0) {
            for (const gId of deletedGalleryIds) {
                const gOld = await client.query('SELECT image_file_id FROM story_gallery_images WHERE id = $1 AND story_id = $2', [gId, id]);
                if (gOld.rows.length > 0) {
                    await deleteFromImageKit(gOld.rows[0].image_file_id);
                    await client.query('DELETE FROM story_gallery_images WHERE id = $1', [gId]);
                }
            }
        }

        // Process New Gallery Images
        if (newGalleryImages && newGalleryImages.length > 0) {
            for (const base64Img of newGalleryImages) {
                const gUpload = await uploadToImageKit(base64Img, 'stories-gallery');
                await client.query(
                    'INSERT INTO story_gallery_images (story_id, image_url, image_file_id) VALUES ($1, $2, $3)',
                    [id, gUpload.url, gUpload.fileId]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'Story updated' });
    } catch (err) { 
        await client.query('ROLLBACK');
        res.status(500).json({ success: false, message: err.message }); 
    } finally {
        client.release();
    }
});

app.delete('/api/admin/stories/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE stories SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Story deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: PROFILES
app.get('/api/admin/profiles', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, photo_url, display_order FROM personal_profiles WHERE deleted_at IS NULL ORDER BY display_order ASC');
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/profiles/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM personal_profiles WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/profiles', requireAdminAuth, async (req, res) => {
    try {
        const countRes = await pool.query('SELECT count(*) FROM personal_profiles WHERE deleted_at IS NULL');
        if (parseInt(countRes.rows[0].count) >= 2) return res.status(400).json({ success: false, message: 'Maximum 2 profiles allowed' });

        const { name, imageBase64, likes, hobbies, description_html } = req.body;
        const upload = await uploadToImageKit(imageBase64, 'profiles');
        const cleanHtml = sanitizeHtml(description_html, sanitizeOptions);

        await pool.query(
            'INSERT INTO personal_profiles (name, photo_url, photo_file_id, likes, hobbies, description_html) VALUES ($1, $2, $3, $4, $5, $6)',
            [name, upload.url, upload.fileId, JSON.stringify(likes), JSON.stringify(hobbies), cleanHtml]
        );
        res.json({ success: true, message: 'Profile created' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/api/admin/profiles/:id', requireAdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, imageBase64, likes, hobbies, description_html } = req.body;
        const cleanHtml = sanitizeHtml(description_html, sanitizeOptions);

        if (imageBase64) {
            const old = await pool.query('SELECT photo_file_id FROM personal_profiles WHERE id = $1', [id]);
            const upload = await uploadToImageKit(imageBase64, 'profiles');
            await pool.query(
                'UPDATE personal_profiles SET name=$1, photo_url=$2, photo_file_id=$3, likes=$4, hobbies=$5, description_html=$6, updated_at=CURRENT_TIMESTAMP WHERE id=$7',
                [name, upload.url, upload.fileId, JSON.stringify(likes), JSON.stringify(hobbies), cleanHtml, id]
            );
            if(old.rows[0].photo_file_id) await deleteFromImageKit(old.rows[0].photo_file_id);
        } else {
            await pool.query(
                'UPDATE personal_profiles SET name=$1, likes=$2, hobbies=$3, description_html=$4, updated_at=CURRENT_TIMESTAMP WHERE id=$5',
                [name, JSON.stringify(likes), JSON.stringify(hobbies), cleanHtml, id]
            );
        }
        res.json({ success: true, message: 'Profile updated' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.delete('/api/admin/profiles/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE personal_profiles SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Profile deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: MOMENTS
app.get('/api/admin/moments', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, image_url, event_date FROM moments WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/moments/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM moments WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.post('/api/admin/moments', requireAdminAuth, async (req, res) => {
    try {
        const { title, event_date, imageBase64 } = req.body;
        const upload = await uploadToImageKit(imageBase64, 'moments');
        await pool.query('INSERT INTO moments (title, event_date, image_url, image_file_id) VALUES ($1, $2, $3, $4)', [title, event_date, upload.url, upload.fileId]);
        res.json({ success: true, message: 'Moment created' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.put('/api/admin/moments/:id', requireAdminAuth, async (req, res) => {
    try {
        const { id } = req.params; const { title, event_date, imageBase64 } = req.body;
        if (imageBase64) {
            const old = await pool.query('SELECT image_file_id FROM moments WHERE id = $1', [id]);
            const upload = await uploadToImageKit(imageBase64, 'moments');
            await pool.query('UPDATE moments SET title=$1, event_date=$2, image_url=$3, image_file_id=$4 WHERE id=$5', [title, event_date, upload.url, upload.fileId, id]);
            if(old.rows[0].image_file_id) await deleteFromImageKit(old.rows[0].image_file_id);
        } else {
            await pool.query('UPDATE moments SET title=$1, event_date=$2 WHERE id=$3', [title, event_date, id]);
        }
        res.json({ success: true, message: 'Moment updated' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.delete('/api/admin/moments/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE moments SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Moment deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: GALLERY
app.get('/api/admin/gallery', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, image_url, event_date, source_type FROM gallery_items WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/gallery/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gallery_items WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.post('/api/admin/gallery', requireAdminAuth, async (req, res) => {
    try {
        const { title, event_date, sourceType, imageBase64, externalUrl } = req.body;
        let url = '', fileId = null;
        if (sourceType === 'upload') {
            const upload = await uploadToImageKit(imageBase64, 'gallery'); url = upload.url; fileId = upload.fileId;
        } else if (sourceType === 'external_url') {
            if (!externalUrl.startsWith('https://')) return res.status(400).json({ success: false, message: 'Invalid URL. Must be HTTPS.' });
            url = externalUrl;
        }
        await pool.query('INSERT INTO gallery_items (title, event_date, image_url, image_file_id, source_type) VALUES ($1, $2, $3, $4, $5)', [title, event_date, url, fileId, sourceType]);
        res.json({ success: true, message: 'Gallery item created' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.put('/api/admin/gallery/:id', requireAdminAuth, async (req, res) => {
    try {
        const { id } = req.params; const { title, event_date, sourceType, imageBase64, externalUrl } = req.body;
        const old = await pool.query('SELECT image_file_id, source_type FROM gallery_items WHERE id = $1', [id]);
        let url = '', fileId = null;
        if (sourceType === 'upload' && imageBase64) {
            const upload = await uploadToImageKit(imageBase64, 'gallery'); url = upload.url; fileId = upload.fileId;
            if(old.rows[0].image_file_id) await deleteFromImageKit(old.rows[0].image_file_id);
            await pool.query('UPDATE gallery_items SET title=$1, event_date=$2, image_url=$3, image_file_id=$4, source_type=$5 WHERE id=$6', [title, event_date, url, fileId, sourceType, id]);
        } else if (sourceType === 'external_url' && externalUrl) {
             if (!externalUrl.startsWith('https://')) return res.status(400).json({ success: false, message: 'Invalid URL' });
             url = externalUrl;
             if(old.rows[0].image_file_id) await deleteFromImageKit(old.rows[0].image_file_id);
             await pool.query('UPDATE gallery_items SET title=$1, event_date=$2, image_url=$3, image_file_id=NULL, source_type=$4 WHERE id=$5', [title, event_date, url, sourceType, id]);
        } else {
             await pool.query('UPDATE gallery_items SET title=$1, event_date=$2 WHERE id=$3', [title, event_date, id]);
        }
        res.json({ success: true, message: 'Gallery item updated' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.delete('/api/admin/gallery/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE gallery_items SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Gallery item deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: VIDEOS
app.get('/api/admin/videos', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, video_url, thumbnail_url, event_date FROM gallery_videos WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/videos/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM gallery_videos WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.post('/api/admin/videos', requireAdminAuth, async (req, res) => {
    try {
        const { title, event_date, video_url } = req.body;
        let ytId = null, thumbUrl = null;
        const ytMatch = video_url.match(/(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/);
        if (ytMatch && ytMatch[1]) { ytId = ytMatch[1]; thumbUrl = `https://img.youtube.com/vi/${ytId}/hqdefault.jpg`; }
        await pool.query('INSERT INTO gallery_videos (title, event_date, video_url, youtube_video_id, thumbnail_url) VALUES ($1, $2, $3, $4, $5)', [title, event_date, video_url, ytId, thumbUrl]);
        res.json({ success: true, message: 'Video created' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.put('/api/admin/videos/:id', requireAdminAuth, async (req, res) => {
    try {
        const { id } = req.params; const { title, event_date, video_url } = req.body;
        let ytId = null, thumbUrl = null;
        const ytMatch = video_url.match(/(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/);
        if (ytMatch && ytMatch[1]) { ytId = ytMatch[1]; thumbUrl = `https://img.youtube.com/vi/${ytId}/hqdefault.jpg`; }
        await pool.query('UPDATE gallery_videos SET title=$1, event_date=$2, video_url=$3, youtube_video_id=$4, thumbnail_url=$5 WHERE id=$6', [title, event_date, video_url, ytId, thumbUrl, id]);
        res.json({ success: true, message: 'Video updated' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.delete('/api/admin/videos/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE gallery_videos SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Video deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: LETTERS
app.get('/api/admin/letters', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, event_date, status FROM letters WHERE deleted_at IS NULL ORDER BY event_date DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/letters/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM letters WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.post('/api/admin/letters', requireAdminAuth, async (req, res) => {
    try {
        const { title, event_date, description_html, status } = req.body;
        const cleanHtml = sanitizeHtml(description_html, sanitizeOptions);
        await pool.query('INSERT INTO letters (title, event_date, description_html, status) VALUES ($1, $2, $3, $4)', [title, event_date, cleanHtml, status]);
        res.json({ success: true, message: 'Letter created' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.put('/api/admin/letters/:id', requireAdminAuth, async (req, res) => {
    try {
        const { id } = req.params; const { title, event_date, description_html, status } = req.body;
        const cleanHtml = sanitizeHtml(description_html, sanitizeOptions);
        await pool.query('UPDATE letters SET title=$1, event_date=$2, description_html=$3, status=$4 WHERE id=$5', [title, event_date, cleanHtml, status, id]);
        res.json({ success: true, message: 'Letter updated' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});
app.delete('/api/admin/letters/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE letters SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Letter deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// Admin CRUD: SONGS
app.get('/api/admin/songs', requireAdminAuth, async (req, res) => {
    const { limit = 10, offset = 0 } = getPagination(req);
    try {
        const result = await pool.query('SELECT id, title, mp3_url, status FROM songs WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
        res.json({ success: true, data: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.get('/api/admin/songs/:id', requireAdminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM songs WHERE id = $1 AND deleted_at IS NULL', [req.params.id]);
        res.json({ success: true, data: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
});
app.post('/api/admin/songs', requireAdminAuth, async (req, res) => {
    const client = await pool.connect();
    try {
        const { title, mp3_url, status } = req.body;
        await client.query('BEGIN');
        if (status === 'active') await client.query("UPDATE songs SET status='nonactive' WHERE status='active' AND deleted_at IS NULL");
        await client.query('INSERT INTO songs (title, mp3_url, status) VALUES ($1, $2, $3)', [title, mp3_url, status]);
        await client.query('COMMIT');
        res.json({ success: true, message: 'Song created' });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ success: false, message: err.message }); } finally { client.release(); }
});
app.put('/api/admin/songs/:id', requireAdminAuth, async (req, res) => {
    const client = await pool.connect();
    try {
        const { id } = req.params; const { title, mp3_url, status } = req.body;
        await client.query('BEGIN');
        if (status === 'active') await client.query("UPDATE songs SET status='nonactive' WHERE status='active' AND id != $1 AND deleted_at IS NULL", [id]);
        await client.query('UPDATE songs SET title=$1, mp3_url=$2, status=$3 WHERE id=$4', [title, mp3_url, status, id]);
        await client.query('COMMIT');
        res.json({ success: true, message: 'Song updated' });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).json({ success: false, message: err.message }); } finally { client.release(); }
});
app.delete('/api/admin/songs/:id', requireAdminAuth, async (req, res) => {
    try {
        await pool.query('UPDATE songs SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1', [req.params.id]);
        res.json({ success: true, message: 'Song deleted' });
    } catch (err) { res.status(500).json({ success: false }); }
});

// 404 Handler
app.use('/api/*', (req, res) => res.status(404).json({ success: false, message: 'API endpoint not found' }));

app.listen(PORT, () => console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode.`));