const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const readline = require('readline-sync');
require('dotenv').config();

async function createAdmin() {
    console.log('\n=== Hiro & Shika Scrapbook - Admin Creation ===\n');
    
    if (!process.env.DATABASE_URL) {
        console.error('Error: DATABASE_URL tidak ditemukan di .env');
        process.exit(1);
    }

    const username = readline.question('Masukkan Username: ');
    if (!username || username.trim() === '') {
        console.error('Error: Username tidak boleh kosong.');
        process.exit(1);
    }

    const password = readline.question('Masukkan Password: ', { hideEchoBack: true });
    if (!password || password.length < 6) {
        console.error('Error: Password minimal 6 karakter.');
        process.exit(1);
    }

    const confirmPassword = readline.question('Konfirmasi Password: ', { hideEchoBack: true });
    if (password !== confirmPassword) {
        console.error('Error: Password tidak cocok.');
        process.exit(1);
    }

    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    try {
        await client.connect();

        // Cek username apakah sudah ada
        const checkQuery = 'SELECT id FROM admin_users WHERE username = $1';
        const checkResult = await client.query(checkQuery, [username]);

        if (checkResult.rows.length > 0) {
            console.error('\nError: Username sudah digunakan. Silakan gunakan username lain.');
            process.exit(1);
        }

        // Hash password dan simpan
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const insertQuery = `
            INSERT INTO admin_users (username, password_hash, role) 
            VALUES ($1, $2, 'admin') RETURNING id, username
        `;
        const result = await client.query(insertQuery, [username, passwordHash]);

        console.log(`\nSukses! Admin dengan username '${result.rows[0].username}' berhasil dibuat.`);
        console.log('Sekarang Anda dapat login ke Dashboard Admin.');

    } catch (error) {
        console.error('\nTerjadi kesalahan saat membuat admin:', error.message);
    } finally {
        await client.end();
        process.exit(0);
    }
}

createAdmin();