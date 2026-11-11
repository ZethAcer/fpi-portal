const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const session = require('express-session');

// 1. Load environment configuration file
require('dotenv').config({ path: './.env' });

// 2. Initialize Express app and set port to 80 for network-wide access
const app = express();
const PORT = 80;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fpi_it_portal_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Serve static frontend files from the current directory
app.use(express.static(path.join(__dirname, 'Public')));

// 3. PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database (fpi_it_portal)');
});

// ==========================================
// AUTHENTICATION & ROOT ROUTES
// ==========================================

app.get('/', (req, res) => {
    const isLoggedOut = !req.session?.user;
    const targetFile = isLoggedOut ? 'index.html' : 'dashboard.html';
    res.sendFile(path.join(__dirname, targetFile));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const loginInput = String(username).trim();
    const cleanPassword = String(password).trim();

    const query = 'SELECT * FROM portal_users WHERE username = $1 OR employee_id = $1 LIMIT 1;';
    const result = await pool.query(query, [loginInput]);

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username/employee ID or password.' });
    }

    const user = result.rows[0];
    const targetUsername = user.username;
    const targetEmployeeId = user.employee_id;

    if (user.status === 'Blocked') {
      return res.status(401).json({ 
        success: false, 
        message: 'Account is locked due to multiple failed login attempts. Please contact IT.' 
      });
    }

    if (cleanPassword !== user.password_hash) {
      const currentFailedAttempts = user.failed_attempts || 0;
      const newFailedAttempts = currentFailedAttempts + 1;

      if (newFailedAttempts >= 3) {
        await pool.query(
          'UPDATE portal_users SET failed_attempts = $1, status = $2 WHERE username = $3',
          [newFailedAttempts, 'Blocked', targetUsername]
        );
        return res.status(401).json({ 
          success: false, 
          message: 'Incorrect password. 3 failed attempts reached. Your account has been blocked.' 
        });
      } else {
        await pool.query(
          'UPDATE portal_users SET failed_attempts = $1 WHERE username = $2',
          [newFailedAttempts, targetUsername]
        );
        const attemptsLeft = 3 - newFailedAttempts;
        return res.status(401).json({ 
          success: false, 
          message: `Incorrect password. You have ${attemptsLeft} attempt(s) left before lockout.` 
        });
      }
    }

    const allowedRoles = ['IT', 'HR', 'IT-Admin', 'HR-Admin'];
    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Access Denied: Your assigned role is not authorized to access the IT Portal.' 
      });
    }

    await pool.query(
      'UPDATE portal_users SET failed_attempts = 0 WHERE username = $1',
      [targetUsername]
    );

    let rosterData = {};
    if (targetEmployeeId) {
        try {
            const rosterQuery = 'SELECT * FROM provisioning_roster WHERE employee_id = $1 LIMIT 1;';
            const rosterResult = await pool.query(rosterQuery, [targetEmployeeId]);
            if (rosterResult.rows.length > 0) {
                rosterData = rosterResult.rows[0];
            }
        } catch (rosterErr) {
            console.warn('Could not fetch from provisioning_roster:', rosterErr.message);
        }
    }

    req.session.user = {
      employee_id: user.employee_id,
      username: user.username,
      role: user.role
    };

    const { password_hash: _, ...userAccountData } = user;
    const userData = {
        ...userAccountData,
        ...rosterData,
        username: targetUsername
    };

    res.json({
      success: true,
      message: 'Login successful',
      user: userData
    });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// Change Password Endpoint with 5-Password History Enforcement
app.post('/api/change_password', async (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  if (!username || !currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const query = 'SELECT * FROM portal_users WHERE username = $1';
    const result = await client.query(query, [username]);

    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const user = result.rows[0];
    const employeeId = user.employee_id;

    if (currentPassword !== user.password_hash) {
      await client.query('ROLLBACK');
      return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
    }

    if (newPassword === user.password_hash) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'New password cannot be the same as your current password.' });
    }

    // Check last 5 password history records
    const historyQuery = `
      SELECT password_hash FROM password_history 
      WHERE employee_id = $1 
      ORDER BY created_at DESC 
      LIMIT 5
    `;
    const historyResult = await client.query(historyQuery, [employeeId]);

    for (let row of historyResult.rows) {
      if (newPassword === row.password_hash) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          success: false, 
          message: 'Security Policy: You cannot reuse any of your last 5 previous passwords.' 
        });
      }
    }

    // Save old password to history
    await client.query(
      'INSERT INTO password_history (employee_id, username, password_hash) VALUES ($1, $2, $3)',
      [employeeId, username, user.password_hash]
    );

    // Update to new password
    await client.query(
      'UPDATE portal_users SET password_hash = $1 WHERE username = $2',
      [newPassword, username]
    );

    await client.query('COMMIT');
    res.json({ success: true, message: 'Password successfully updated.' });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Change password error:', err.message);
    res.status(500).json({ success: false, message: 'Server database error during password update.' });
  } finally {
    client.release();
  }
});

app.post('/api/verify_admin_password', async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = 'SELECT * FROM portal_users WHERE username = $1';
    const result = await pool.query(query, [username]);

    if (result.rows.length === 0) {
      return res.json({ success: false, message: 'User not found.' });
    }

    const user = result.rows[0];
    if (password !== user.password_hash) {
      return res.json({ success: false, message: 'Incorrect password.' });
    }

    res.json({ 
      success: true, 
      message: 'Password verified.', 
      user: { username: user.username, role: user.role } 
    });
  } catch (err) {
    console.error('Error verifying admin password:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// ==========================================
// USER MANAGEMENT ROUTES
// ==========================================

app.get('/api/portal_users', async (req, res) => {
  try {
    const query = `
      SELECT user_id, employee_id, employee_firstname, employee_middlename, employee_lastname, 
             username, password_hash, role, failed_attempts, status, created_at 
      FROM portal_users 
      ORDER BY user_id ASC
    `;
    const result = await pool.query(query);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching portal users:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// Unlock Account: Archives old password into history & generates 12-char temp password
app.post('/api/portal_users/unlock', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'Target username is required.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userQuery = 'SELECT * FROM portal_users WHERE username = $1';
    const userResult = await client.query(userQuery, [username]);

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Target user not found.' });
    }

    const user = userResult.rows[0];
    const employeeId = user.employee_id;
    const oldPasswordHash = user.password_hash;

    // Archive previous password to history
    await client.query(
      'INSERT INTO password_history (employee_id, username, password_hash) VALUES ($1, $2, $3)',
      [employeeId, username, oldPasswordHash]
    );

    // Generate 12-character random temp password
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$!';
    let tempPassword = '';
    for (let i = 0; i < 12; i++) {
      tempPassword += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const updateQuery = `
      UPDATE portal_users 
      SET failed_attempts = 0, status = 'Active', password_hash = $1 
      WHERE username = $2
    `;
    await client.query(updateQuery, [tempPassword, username]);

    await client.query('COMMIT');
    res.json({ 
      success: true, 
      message: `Account ${username} successfully unlocked.`, 
      tempPassword: tempPassword 
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error unlocking user account:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  } finally {
    client.release();
  }
});

// ==========================================
// HARDWARE ASSETS API ENDPOINTS
// ==========================================

app.get('/api/hardware_assets', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM hardware_assets ORDER BY id_serial DESC');
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching hardware assets:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

app.get('/api/hardware_assets/code/:code', async (req, res) => {
  const { code } = req.params;
  try {
    const query = 'SELECT * FROM hardware_assets WHERE item_code = $1 OR id_serial::text = $1 LIMIT 1;';
    const result = await pool.query(query, [code]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Hardware asset not found.' });
    }

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error fetching hardware asset by code:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

app.post('/api/hardware_assets', async (req, res) => {
  const {
    department, team, category, model_name, brand_model,
    desktop_name, item_code, serial_number, product_id,
    os_version, status, location, assigned_user, date_endorsed, remarks
  } = req.body;

  try {
    const query = `
      INSERT INTO hardware_assets (
        department, team, category, model_name, brand_model,
        desktop_name, item_code, serial_number, product_id,
        os_version, status, location, assigned_user, date_endorsed, remarks
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *;
    `;
    const values = [
      department || null, team || null, category || null, model_name || null, brand_model || null,
      desktop_name || null, item_code || null, serial_number || null, product_id || null,
      os_version || null, status || 'Operational', location || null, assigned_user || null,
      date_endorsed || null, remarks || null
    ];

    const result = await pool.query(query, values);
    res.json({ success: true, message: 'Asset added successfully', asset: result.rows[0] });
  } catch (err) {
    console.error('Error adding hardware asset:', err.message);
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'Duplicate unique field (Item code or serial number already exists).' });
    }
    res.status(500).json({ success: false, message: 'Database error: ' + err.message });
  }
});

app.put('/api/hardware_assets/:id', async (req, res) => {
  const { id } = req.params;
  const {
    department, team, category, model_name, brand_model,
    desktop_name, item_code, serial_number, product_id,
    os_version, status, location, assigned_user, date_endorsed, remarks
  } = req.body;

  try {
    const query = `
      UPDATE hardware_assets 
      SET department = $1, team = $2, category = $3, model_name = $4, brand_model = $5,
          desktop_name = $6, item_code = $7, serial_number = $8, product_id = $9,
          os_version = $10, status = $11, location = $12, assigned_user = $13, 
          date_endorsed = $14, remarks = $15
      WHERE id_serial::text = $16 OR item_code = $17
      RETURNING *;
    `;
    const values = [
      department || null, team || null, category || null, model_name || null, brand_model || null,
      desktop_name || null, item_code || null, serial_number || null, product_id || null,
      os_version || null, status || 'Operational', location || null, assigned_user || null,
      date_endorsed || null, remarks || null,
      id, item_code
    ];

    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Hardware asset not found.' });
    }

    res.json({ success: true, message: 'Asset updated successfully', asset: result.rows[0] });
  } catch (err) {
    console.error('Error updating hardware asset:', err.message);
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  }
});

app.delete('/api/hardware_assets/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM hardware_assets WHERE id_serial::text = $1 OR item_code = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Asset not found' });
    }
    res.json({ success: true, message: 'Asset deleted successfully' });
  } catch (err) {
    console.error('Error deleting asset:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// ==========================================
// ACCESS AUDIT LOGS ROUTES
// ==========================================

app.get('/api/access_audit_logs', async (req, res) => {
  try {
    const query = `SELECT * FROM access_audit_logs ORDER BY created_at DESC;`;
    const result = await pool.query(query);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching audit logs:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

app.post('/api/access_audit_logs', async (req, res) => {
  const {
    application_date, action_type, employee_id, employee_firstname, employee_middlename, employee_lastname,
    department, employee_manager, assigned_userid, system_application_name, access_level,
    business_jurisdiction, approval_method, approval_status, processed_by, execution_date, retention_expiry_date
  } = req.body;

  try {
    const currentYear = new Date().getFullYear();
    const maxQuery = await pool.query(
      `SELECT MAX(CAST(SUBSTRING(log_id FROM '[0-9]+$') AS INTEGER)) as max_num 
       FROM access_audit_logs 
       WHERE log_id LIKE $1`,
      [`AUD-${currentYear}-%`]
    );

    const nextSeq = (maxQuery.rows[0].max_num || 0) + 1;
    const log_id = `AUD-${currentYear}-${String(nextSeq).padStart(4, '0')}`;

    const query = `
      INSERT INTO access_audit_logs 
        (log_id, application_date, action_type, employee_id, employee_firstname, employee_middlename, employee_lastname,
         department, employee_manager, assigned_userid, system_application_name, access_level,
         business_jurisdiction, approval_method, approval_status, processed_by, execution_date, retention_expiry_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *;
    `;
    const values = [
      log_id, application_date, action_type, employee_id, employee_firstname, employee_middlename || null, employee_lastname,
      department, employee_manager, assigned_userid, system_application_name, access_level,
      business_jurisdiction, approval_method, approval_status || 'Pending', processed_by, execution_date || null, retention_expiry_date || null
    ];

    const result = await pool.query(query, values);
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error creating audit log:', err.message);
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  }
});

app.put('/api/access_audit_logs/:id', async (req, res) => {
  const { id } = req.params;
  const {
    application_date, action_type, employee_id, employee_firstname, employee_middlename, employee_lastname,
    department, employee_manager, assigned_userid, system_application_name, access_level,
    business_jurisdiction, approval_method, approval_status, processed_by, execution_date, retention_expiry_date
  } = req.body;

  try {
    const query = `
      UPDATE access_audit_logs 
      SET application_date = $1, action_type = $2, employee_id = $3, employee_firstname = $4, 
          employee_middlename = $5, employee_lastname = $6, department = $7, employee_manager = $8, 
          assigned_userid = $9, system_application_name = $10, access_level = $11, 
          business_jurisdiction = $12, approval_method = $13, approval_status = $14, 
          processed_by = $15, execution_date = $16, retention_expiry_date = $17
      WHERE log_id = $18
      RETURNING *;
    `;
    const values = [
      application_date, action_type, employee_id, employee_firstname, employee_middlename || null, employee_lastname,
      department, employee_manager, assigned_userid, system_application_name, access_level,
      business_jurisdiction, approval_method, approval_status || 'Pending', processed_by, 
      execution_date || null, retention_expiry_date || null,
      id
    ];

    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Audit log record not found.' });
    }

    res.json({ success: true, message: 'Audit log updated successfully', data: result.rows[0] });
  } catch (err) {
    console.error('Error updating audit log:', err.message);
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  }
});

// ==========================================
// PROVISIONING ROSTER & USER REGISTRATION ROUTES
// ==========================================

app.get('/api/provisioning_roster', async (req, res) => {
  try {
    const query = `
      SELECT r.id, r.employee_id, r.employee_firstname, r.employee_middlename, r.employee_lastname,
             r.department, r.job_title, r.manager_name, r.employee_status, r.effective_date, r.created_at,
             u.username, u.role
      FROM provisioning_roster r
      LEFT JOIN portal_users u ON r.employee_id = u.employee_id
      ORDER BY r.employee_id DESC;
    `;
    const result = await pool.query(query);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching provisioning roster:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

app.get('/api/provisioning_roster/lookup/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const query = 'SELECT * FROM provisioning_roster WHERE employee_id::text = $1 LIMIT 1;';
        const result = await pool.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Employee not found in roster.' });
        }

        res.json({ success: true, data: result.rows[0] });
    } catch (err) {
        console.error('Error looking up roster employee:', err.message);
        res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
    }
});

app.post('/api/provisioning_roster', async (req, res) => {
  const {
    employee_id, employee_firstname, employee_middlename, employee_lastname,
    department, job_title, manager_name, employee_status, effective_date,
    temp_password, role
  } = req.body;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Check if employee already exists in provisioning_roster (Supports Edit/Upsert)
    const existingRoster = await client.query('SELECT * FROM provisioning_roster WHERE employee_id = $1', [employee_id]);

    const cleanRole = String(role || 'User').trim();
    const isApprover = cleanRole === 'IT-Admin' || cleanRole === 'HR-Admin' || cleanRole === 'QC-Admin' || cleanRole === 'Admin';

    if (existingRoster.rows.length > 0) {
      // ---> UPDATE EXISTING EMPLOYEE RECORD <---
      const updateRosterQuery = `
        UPDATE provisioning_roster 
        SET employee_firstname = $2, employee_middlename = $3, employee_lastname = $4, 
            department = $5, job_title = $6, manager_name = $7, employee_status = $8, effective_date = $9
        WHERE employee_id = $1
        RETURNING *;
      `;
      const updateValues = [
        employee_id, employee_firstname, employee_middlename || null, employee_lastname,
        department, job_title, manager_name || null, employee_status || 'Active', effective_date || null
      ];
      const rosterResult = await client.query(updateRosterQuery, updateValues);

      // Also update portal_users role, names, and is_approver flag
      if (role) {
        await client.query(
          'UPDATE portal_users SET role = $1, employee_firstname = $2, employee_lastname = $3, is_approver = $5 WHERE employee_id = $4',
          [cleanRole, employee_firstname, employee_lastname, employee_id, isApprover]
        );
      }

      await client.query('COMMIT');
      return res.json({ success: true, data: rosterResult.rows[0], message: 'Employee record updated successfully.' });
    }

    // ---> INSERT NEW EMPLOYEE RECORD <---
    let cleanFirst = (employee_firstname || '').trim().toLowerCase().replace(/[^a-z]/g, '');
    let cleanLast = (employee_lastname || '').trim().toLowerCase().replace(/[^a-z]/g, '');
    if (!cleanFirst) cleanFirst = "user";
    if (!cleanLast) cleanLast = "employee";

    const existingRes = await client.query('SELECT username FROM portal_users');
    const existingUsernames = existingRes.rows.map(u => u.username ? u.username.toLowerCase() : '');

    let generatedUsername = "";
    let charCount = 1;
    let foundUnique = false;

    while (charCount <= cleanFirst.length) {
      let prefix = cleanFirst.substring(0, charCount);
      let candidate = prefix + cleanLast;
      if (!existingUsernames.includes(candidate)) {
        generatedUsername = candidate;
        foundUnique = true;
        break;
      }
      charCount++;
    }

    if (!foundUnique) {
      generatedUsername = cleanFirst + cleanLast + Math.floor(Math.random() * 1000);
    }

    const rosterQuery = `
      INSERT INTO provisioning_roster 
        (employee_id, employee_firstname, employee_middlename, employee_lastname, department, job_title, manager_name, employee_status, effective_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *;
    `;
    const rosterValues = [
      employee_id, employee_firstname, employee_middlename || null, employee_lastname,
      department, job_title, manager_name || null, employee_status || 'Active', effective_date || null
    ];
    const rosterResult = await client.query(rosterQuery, rosterValues);

    const userQuery = `
      INSERT INTO portal_users 
        (employee_id, username, password_hash, employee_firstname, employee_lastname, role, is_approver, status, failed_attempts, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, CURRENT_TIMESTAMP)
      RETURNING *;
    `;
    const userValues = [
      employee_id, generatedUsername, temp_password, employee_firstname, employee_lastname, 
      cleanRole, isApprover, employee_status === 'Active' ? 'Active' : 'Pending'
    ];
    await client.query(userQuery, userValues);

    // ---> AUTOMATICALLY ADD TO ACCESS AUDIT LOGS WITH SPECIFIED FORMAT & FIELDS <---
    const currentYear = new Date().getFullYear();
    const maxQuery = await client.query(
      `SELECT MAX(CAST(SUBSTRING(log_id FROM '[0-9]+$') AS INTEGER)) as max_num 
       FROM access_audit_logs 
       WHERE log_id LIKE $1`,
      [`AUD-${currentYear}-%`]
    );

    const nextSeq = (maxQuery.rows[0].max_num || 0) + 1;
    const log_id = `AUD-${currentYear}-${String(nextSeq).padStart(4, '0')}`;
    
    // Calculate dates
    const todayDate = effective_date ? new Date(effective_date) : new Date();
    const executionDateStr = todayDate.toISOString().split('T')[0];
    
    // Calculate retention expiry date (+3 years)
    const expiryDate = new Date(todayDate);
    expiryDate.setFullYear(expiryDate.getFullYear() + 3);
    const retentionExpiryStr = expiryDate.toISOString().split('T')[0];

    const auditQuery = `
      INSERT INTO access_audit_logs 
        (log_id, application_date, action_type, employee_id, employee_firstname, employee_middlename, employee_lastname,
         department, employee_manager, assigned_userid, system_application_name, access_level,
         business_jurisdiction, approval_method, approval_status, processed_by, execution_date, retention_expiry_date)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18);
    `;
    const auditValues = [
      log_id,
      executionDateStr,
      'Grant Access',
      employee_id,
      employee_firstname,
      employee_middlename || null,
      employee_lastname,
      department,
      manager_name || 'HR / IT Management',
      generatedUsername,
      'FPI Portal',
      cleanRole,
      'Batino Branch',
      'Email Approval',
      'Approved',
      req.session?.user?.username || 'System Admin',
      executionDateStr,
      retentionExpiryStr
    ];

    await client.query(auditQuery, auditValues);

    await client.query('COMMIT');
    res.json({ success: true, data: rosterResult.rows[0], username: generatedUsername, message: 'Employee successfully onboarded and logged in audit trails.' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error creating roster record & audit log:', err.message);
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'Employee ID or Username already exists.' });
    }
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  } finally {
    client.release();
  }
});

app.delete('/api/provisioning_roster/:id', async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const findRes = await client.query('SELECT employee_id FROM provisioning_roster WHERE id::text = $1 OR employee_id = $1', [id]);
    
    const result = await client.query('DELETE FROM provisioning_roster WHERE id::text = $1 OR employee_id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Roster record not found' });
    }

    if (findRes.rows.length > 0) {
      const empNum = findRes.rows[0].employee_id;
      await client.query('DELETE FROM portal_users WHERE employee_id = $1', [empNum]);
    }

    await client.query('COMMIT');
    res.json({ success: true, message: 'Roster record and associated portal account deleted successfully' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error deleting roster record:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  } finally {
    client.release();
  }
});

// ==========================================
// ASSET BORROWING ROUTES
// ==========================================

app.get('/api/asset_borrowing', async (req, res) => {
    try {
        const query = `SELECT * FROM borrowing_logs ORDER BY log_id DESC`;
        const result = await pool.query(query);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('Error fetching asset borrowing records:', err);
        res.status(500).json({ success: false, message: 'Server error while fetching borrowing logs.' });
    }
});

// ==========================================
// IT SUPPORT TICKETS ROUTES
// ==========================================

app.get('/api/support_tickets', async (req, res) => {
    try {
        const query = `
            SELECT *, 
                   EXTRACT(DAY FROM (COALESCE(date_resolved::timestamp, CURRENT_TIMESTAMP) - date::timestamp))::int AS days_open
            FROM it_support_tickets 
            ORDER BY ticket_id DESC;
        `;
        const result = await pool.query(query);
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error('Error fetching support tickets:', err.message);
        res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
    }
});

app.post('/api/support_tickets', async (req, res) => {
    const {
        employee_id, employee_firstname, employee_middlename, employee_lastname,
        department, issue_type, task_description, priority, assigned_to, remarks
    } = req.body;

    try {
        const now = new Date();
        const currentYear = now.getFullYear();
        const currentMonth = String(now.getMonth() + 1).padStart(2, '0');
        const yearMonthPrefix = `${currentYear}${currentMonth}`;

        const maxQuery = await pool.query(
            `SELECT MAX(CAST(SUBSTRING(ticket_id FROM '[0-9]+$') AS INTEGER)) as max_num 
             FROM it_support_tickets 
             WHERE ticket_id LIKE $1`,
            [`TKT-${yearMonthPrefix}-%`]
        );

        const nextSeq = (maxQuery.rows[0].max_num || 0) + 1;
        const ticket_id = `TKT-${yearMonthPrefix}-${String(nextSeq).padStart(4, '0')}`;
        const currentDate = now.toISOString().split('T')[0];

        const query = `
            INSERT INTO it_support_tickets 
                (ticket_id, date, employee_id, employee_firstname, employee_middlename, employee_lastname,
                 department, issue_type, priority, status, assigned_to, task_description, remarks)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *;
        `;
        const values = [
            ticket_id,
            currentDate,
            employee_id || null,
            employee_firstname,
            employee_middlename || null,
            employee_lastname,
            department,
            issue_type || 'Hardware',
            priority || 'Medium',
            'Open',
            assigned_to || null,
            task_description,
            remarks || null
        ];

        const result = await pool.query(query, values);
        res.json({ success: true, message: 'Support ticket created successfully.', data: result.rows[0] });
    } catch (err) {
        console.error('Error creating support ticket:', err.message);
        res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
    }
});

app.put('/api/support_tickets/:id', async (req, res) => {
    const { id } = req.params;
    const {
        issue_type, priority, status, date_resolved, assigned_to, task_description, remarks
    } = req.body;

    try {
        const query = `
            UPDATE it_support_tickets 
            SET issue_type = $1, priority = $2, status = $3, date_resolved = $4, 
                assigned_to = $5, task_description = $6, remarks = $7
            WHERE ticket_id = $8
            RETURNING *;
        `;
        const values = [
            issue_type,
            priority,
            status,
            date_resolved || null,
            assigned_to || null,
            task_description,
            remarks || null,
            id
        ];

        const result = await pool.query(query, values);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Support ticket not found.' });
        }

        res.json({ success: true, message: 'Support ticket updated successfully', data: result.rows[0] });
    } catch (err) {
        console.error('Error updating support ticket:', err.message);
        res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
    }
});

app.delete('/api/support_tickets/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM it_support_tickets WHERE ticket_id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Support ticket not found.' });
        }
        res.json({ success: true, message: 'Support ticket deleted successfully.' });
    } catch (err) {
        console.error('Error deleting support ticket:', err.message);
        res.status(500).json({ success: false, message: 'Server database error' });
    }
});

// ==========================================
// STORAGE & REPOSITORY ROUTES
// ==========================================

app.get('/api/storage_repository', async (req, res) => {
  try {
    const query = `
      SELECT id, storage_id, file_name, category, serial_number, version_tag, 
             used_capacity, file_size, file_path_or_url, date_updated, 
             updated_by, backup_status, remarks, created_at
      FROM storage_repository
      ORDER BY id DESC;
    `;
    const result = await pool.query(query);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching storage repository:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

app.post('/api/storage_repository', async (req, res) => {
  const {
    storage_id, file_name, category, serial_number, version_tag,
    used_capacity, file_size, file_path_or_url, date_updated,
    updated_by, backup_status, remarks
  } = req.body;

  try {
    const query = `
      INSERT INTO storage_repository (
        storage_id, file_name, category, serial_number, version_tag,
        used_capacity, file_size, file_path_or_url, date_updated,
        updated_by, backup_status, remarks
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `;
    const values = [
      storage_id, file_name, category, serial_number || null, version_tag || null,
      used_capacity || null, file_size || null, file_path_or_url, date_updated || null,
      updated_by || 'IT Staff', backup_status || 'Success', remarks || null
    ];

    const result = await pool.query(query, values);
    res.json({ success: true, message: 'Storage record added successfully', data: result.rows[0] });
  } catch (err) {
    console.error('Error adding storage record:', err.message);
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'Storage ID already exists.' });
    }
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  }
});

app.put('/api/storage_repository/:id', async (req, res) => {
  const { id } = req.params;
  const {
    storage_id, file_name, category, serial_number, version_tag,
    used_capacity, file_size, file_path_or_url, date_updated,
    updated_by, backup_status, remarks
  } = req.body;

  try {
    const query = `
      UPDATE storage_repository 
      SET storage_id = $1, file_name = $2, category = $3, serial_number = $4, version_tag = $5,
          used_capacity = $6, file_size = $7, file_path_or_url = $8, date_updated = $9,
          updated_by = $10, backup_status = $11, remarks = $12
      WHERE id::text = $13 OR storage_id = $14
      RETURNING *;
    `;
    const values = [
      storage_id, file_name, category, serial_number || null, version_tag || null,
      used_capacity || null, file_size || null, file_path_or_url, date_updated || null,
      updated_by || 'IT Staff', backup_status || 'Success', remarks || null,
      id, storage_id
    ];

    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Storage record not found.' });
    }

    res.json({ success: true, message: 'Storage record updated successfully', data: result.rows[0] });
  } catch (err) {
    console.error('Error updating storage record:', err.message);
    res.status(500).json({ success: false, message: 'Server database error: ' + err.message });
  }
});

app.delete('/api/storage_repository/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM storage_repository WHERE id::text = $1 OR storage_id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Storage record not found.' });
    }
    res.json({ success: true, message: 'Storage record deleted successfully.' });
  } catch (err) {
    console.error('Error deleting storage record:', err.message);
    res.status(500).json({ success: false, message: 'Server database error' });
  }
});

// ==========================================
// BIND SERVER TO '0.0.0.0' AND PORT 80
// ==========================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 FPI IT Portal server running live on network at http://0.0.0.0:${PORT}`);
});
