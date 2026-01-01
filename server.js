// =====================
// IMPORTS
// =====================
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');

// =====================
// APP & DATABASE
// =====================
const app = express();
const db = new sqlite3.Database("database.db", (err) => {
  if (err) {
    console.error('Failed to open database', err);
    process.exit(1);
  }
});

const dbRun = (...args) => new Promise((resolve, reject) => {
  db.run(...args, function(err) {
    if (err) return reject(err);
    resolve(this);
  });
});
const dbGet = promisify(db.get.bind(db));
const dbAll = promisify(db.all.bind(db));

// =====================
// MIDDLEWARE
// =====================
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "cargo-king-secret",
  resave: false,
  saveUninitialized: false
}));

const expressLayouts = require('express-ejs-layouts');

// Role hierarchy helper
const ROLE_RANK = { trucker: 1, supervisor: 2, manager: 3, executive: 4, admin: 4 };
function hasRoleAtLeast(userRole, requiredRole) {
  const a = ROLE_RANK[userRole] || 0;
  const b = ROLE_RANK[requiredRole] || 0;
  return a >= b;
}

// Can the assigner role set the desired role? This enforces a simple
// delegation model: executives can set anyone, managers can set supervisors
// and truckers, and supervisors can set truckers.
function canAssignRole(assignerRole, desiredRole) {
  if (!assignerRole) return false;
  const map = {
    executive: ['executive','manager','supervisor','trucker'],
    manager: ['supervisor','trucker'],
    supervisor: ['trucker']
  };
  return (map[assignerRole] || []).includes(desiredRole);
}

// Make `user` available in all templates
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// Minimal flash implementation
app.use((req, res, next) => {
  res.locals.flash = req.session.flash;
  delete req.session.flash;
  next();
});

// CSRF protection (uses session)
const csurf = require('csurf');
app.use(csurf());
app.use((req, res, next) => {
  try {
    res.locals.csrfToken = req.csrfToken();
  } catch (e) {
    // If csurf isn't available or token generation fails, ensure token is an empty string
    res.locals.csrfToken = '';
  }
  next();
});

// Ensure safe defaults for template locals to avoid repetitive guards in views
app.use((req, res, next) => {
  res.locals.csrfToken = typeof res.locals.csrfToken !== 'undefined' ? res.locals.csrfToken : '';
  res.locals.bodyClass = res.locals.bodyClass || '';
  res.locals.user = req.session.user || null;
  res.locals.flash = typeof res.locals.flash !== 'undefined' ? res.locals.flash : null;
  next();
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    console.error('CSRF validation failed', {
      cookies: req.headers.cookie,
      body: req.body,
      sessionUser: req.session && req.session.user ? { id: req.session.user.id, username: req.session.user.username, role: req.session.user.role } : null
    });

    // Try to provide a more specific flash when the CSRF fail happens during an admin role assignment
    if (req.body && req.body.role === 'executive' && req.session && req.session.user && req.session.user.role === 'supervisor') {
      req.session.flash = { type: 'error', message: 'Only executives can create executive users' };
      return res.redirect('/admin');
    }

    res.status(403);
    req.session.flash = { type: 'error', message: 'Form tampered with (CSRF token missing or invalid).' };
    return res.redirect('back');
  }
  next(err);
});

// Use EJS layouts so `layout.ejs` wraps all views
app.use(expressLayouts);
app.set('layout', 'layout');

app.set("view engine", "ejs");

// =====================
// DATABASE TABLES
// =====================
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  badge INTEGER UNIQUE,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT,
  hours INTEGER DEFAULT 0,
  deliveries INTEGER DEFAULT 0,
  created_at TEXT
)
`).run();

// Add missing columns on older DBs (migration)
try {
  db.prepare("ALTER TABLE users ADD COLUMN badge INTEGER").run();
} catch (e) {}
try {
  db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_badge ON users(badge)").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE users ADD COLUMN created_at TEXT").run();
} catch (e) {}

// Add newer columns to logs if missing: plate, deliveries (per-log), notes
try {
  db.prepare("ALTER TABLE logs ADD COLUMN plate TEXT").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE logs ADD COLUMN deliveries INTEGER DEFAULT 0").run();
} catch (e) {}
try {
  db.prepare("ALTER TABLE logs ADD COLUMN notes TEXT").run();
} catch (e) {}

db.prepare(`
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  vehicle TEXT,
  damage TEXT,
  fuel INTEGER,
  insurance TEXT,
  created_at TEXT
)
`).run();

// Add hours column to logs if it doesn't exist (so we can revert hours on delete)
try {
  db.prepare("ALTER TABLE logs ADD COLUMN hours INTEGER DEFAULT 0").run();
} catch (e) {
  // ignore if column already exists
}

// Admin audit actions table
async function initDatabase() {
  try {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      badge INTEGER UNIQUE,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT,
      hours INTEGER DEFAULT 0,
      deliveries INTEGER DEFAULT 0,
      created_at TEXT
    )`);

    await dbRun(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_badge ON users(badge)`);

    await dbRun(`CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      vehicle TEXT,
      damage TEXT,
      fuel INTEGER,
      insurance TEXT,
      created_at TEXT,
      plate TEXT,
      deliveries INTEGER DEFAULT 0,
      notes TEXT,
      hours INTEGER DEFAULT 0
    )`);

    await dbRun(`CREATE TABLE IF NOT EXISTS admin_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id INTEGER,
      action TEXT,
      target_id INTEGER,
      details TEXT,
      created_at TEXT
    )`);

    // Migrations: attempt to add columns if missing, ignore errors
    const migrations = [
      `ALTER TABLE users ADD COLUMN badge INTEGER`,
      `ALTER TABLE users ADD COLUMN created_at TEXT`,
      `ALTER TABLE logs ADD COLUMN plate TEXT`,
      `ALTER TABLE logs ADD COLUMN deliveries INTEGER DEFAULT 0`,
      `ALTER TABLE logs ADD COLUMN notes TEXT`,
      `ALTER TABLE logs ADD COLUMN hours INTEGER DEFAULT 0`
    ];

    for (const sql of migrations) {
      try {
        await dbRun(sql);
      } catch (e) {
        // ignore if column exists or other migration error
      }
    }

    // Default executive account
    const adminExists = await dbGet("SELECT * FROM users WHERE username = ?", ['admin']);
    if (!adminExists) {
      await dbRun(`INSERT INTO users (badge, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)`,
        [1000, 'admin', bcrypt.hashSync('admin123', 10), 'executive', new Date().toISOString()]);
    }

    console.log('Database initialized');
  } catch (e) {
    console.error('Database initialization failed', e);
    throw e;
  }
}

async function recordAdminAction(adminId, action, targetId, details) {
  try {
    await dbRun(`INSERT INTO admin_actions (admin_id, action, target_id, details, created_at) VALUES (?, ?, ?, ?, ?)`,
      adminId, action, targetId || null, details ? JSON.stringify(details) : null, new Date().toISOString());
  } catch (e) {
    console.error('Failed to record admin action', e);
  }
}

// =====================
// DEFAULT EXECUTIVE ACCOUNT
// =====================
const adminExists = db.prepare(
  "SELECT * FROM users WHERE username = ?"
).get("admin");

if (!adminExists) {
  db.prepare(`
    INSERT INTO users (badge, username, password, role, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    1000,
    "admin",
    bcrypt.hashSync("admin123", 10),
    "executive",
    new Date().toISOString()
  );
}

// =====================
// AUTH MIDDLEWARE
// =====================
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role === "trucker")
    return res.status(403).render("403");
  next();
}

// Friendly 403 page route (handy for direct visits)
app.get("/403", (req, res) => {
  res.status(403).render("403");
});

// =====================
// ROUTES — AUTH
// =====================
app.get("/", (req, res) => {
  res.render("login", { bodyClass: 'auth', csrfToken: res.locals.csrfToken });
});

app.get("/signup", (req, res) => {
  res.render("signup", { bodyClass: 'auth', csrfToken: res.locals.csrfToken });
});

app.post("/login", async (req, res) => {
  try {
    const user = await dbGet("SELECT * FROM users WHERE username = ?", [req.body.username]);

    if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
      return res.status(401).send("Invalid username or password");
    }

    // Store only minimal user info in session (avoid storing password hash)
    req.session.user = {
      id: user.id,
      badge: user.badge,
      username: user.username,
      role: user.role,
      hours: user.hours,
      deliveries: user.deliveries
    };

    res.redirect("/dashboard");
  } catch (e) {
    console.error('Login error', e);
    res.status(500).send('Server error');
  }
});

// signup route consolidated (duplicate removed)

app.post("/signup", async (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10);

  // Public signups should always be regular truckers for safety
  const publicRole = 'trucker';

  try {
    await dbRun(`INSERT INTO users (badge, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)`,
      req.body.badge,
      req.body.username,
      hash,
      publicRole,
      new Date().toISOString()
    );
  } catch (e) {
    req.session.flash = { type: 'error', message: 'Badge or username already exists' };
    return res.redirect('/signup');
  }

  req.session.flash = { type: 'success', message: 'Account created — please log in' };
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// =====================
// ROUTES — DASHBOARD
// =====================
app.get("/dashboard", requireLogin, async (req, res) => {
  try {
    // Always fetch the latest user info
    const user = await dbGet("SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?", [req.session.user.id]);

    let logs;
    if (user.role === 'trucker') {
      logs = await dbAll(`
        SELECT logs.*, users.username
        FROM logs
        JOIN users ON users.id = logs.user_id
        WHERE user_id = ?
        ORDER BY logs.created_at DESC
      `, [user.id]);
    } else {
      // non-trucker roles can see all logs
      logs = await dbAll(`
        SELECT logs.*, users.username
        FROM logs
        JOIN users ON users.id = logs.user_id
        ORDER BY logs.created_at DESC
      `);
    }

    // Debug: ensure CSRF and user are present for template rendering
    console.log('DEBUG /dashboard: req.session.user=', !!req.session.user ? { id: req.session.user.id, username: req.session.user.username, role: req.session.user.role } : null, 'res.locals.csrfToken defined=', typeof res.locals.csrfToken !== 'undefined');
    try { console.log('DEBUG /dashboard: req.csrfToken available=', typeof req.csrfToken === 'function'); } catch (e) { console.log('DEBUG /dashboard: req.csrfToken() threw'); }

    res.render("dashboard", {
      user,
      logs,
      csrfToken: res.locals.csrfToken
    });
  } catch (e) {
    console.error('ERROR rendering dashboard:', e && e.stack ? e.stack : e);
    throw e;
  }
});

// =====================
// ROUTES — LOG WORK
// =====================
app.get("/logs", requireLogin, (req, res) => {
  res.render("logs", { user: req.session.user, csrfToken: res.locals.csrfToken });
});

// duplicate profile route removed; consolidated later in file

app.post("/log", requireLogin, async (req, res) => {
  try {
    const user = req.session.user;
    const hoursToAdd = Number(req.body.hours) || 0;
    // Accept fuel as a category string (e.g., "below 20%", "20-50%", ...)
    const fuelCategory = req.body.fuel || req.body.fuel_level || '';
    const damage = req.body.damage || 'None';
    const plate = req.body.plate || '';
    const notes = req.body.notes || '';
    const deliveriesReported = Number(req.body.deliveries) || 0;
    const deliveriesToAdd = deliveriesReported > 0 ? deliveriesReported : 1; // default to 1 to preserve previous behaviour

    await dbRun(`INSERT INTO logs (user_id, vehicle, plate, deliveries, damage, fuel, insurance, notes, created_at, hours) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      user.id,
      req.body.vehicle,
      plate,
      deliveriesToAdd,
      damage,
      fuelCategory,
      req.body.insurance,
      notes,
      new Date().toISOString(),
      hoursToAdd
    );

    await dbRun(`UPDATE users SET hours = hours + ?, deliveries = deliveries + ? WHERE id = ?`,
      hoursToAdd,
      deliveriesToAdd,
      user.id
    );

    // Refresh session user with latest stats
    const updatedUser = await dbGet("SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?", [user.id]);
    req.session.user = updatedUser;
    res.locals.user = updatedUser;

    res.redirect("/dashboard");
  } catch (e) {
    console.error('/log error', e);
    res.status(500).send('Server error');
  }
});

app.post('/logs/:id/delete', requireLogin, async (req, res) => {
  try {
    const id = req.params.id;
    const log = await dbGet('SELECT * FROM logs WHERE id = ?', [id]);
    if (!log) return res.status(404).send('Log not found');

    // Only owner or non-trucker roles can delete
    if (log.user_id !== req.session.user.id && req.session.user.role === 'trucker') {
      return res.status(403).render('403');
    }

    await dbRun('DELETE FROM logs WHERE id = ?', id);

    // Adjust user's totals if possible
    if (log.user_id) {
      await dbRun('UPDATE users SET hours = hours - ?, deliveries = deliveries - 1 WHERE id = ?', log.hours || 0, log.user_id);

      if (log.user_id === req.session.user.id) {
        // Refresh session user
        const updatedUser = await dbGet("SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?", [log.user_id]);
        req.session.user = updatedUser;
        res.locals.user = updatedUser;
      }
    }

    res.redirect('/dashboard');
  } catch (e) {
    console.error('/logs/:id/delete error', e);
    res.status(500).send('Server error');
  }
});

// =====================
// ROUTES — ADMIN PANEL
// =====================
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    console.log('ADMIN GET: session user=', req.session.user && req.session.user.role, 'cookies=', req.headers.cookie);
    console.log('ADMIN GET: res.locals.csrfToken defined=', typeof res.locals.csrfToken !== 'undefined', 'value length=', typeof res.locals.csrfToken === 'string' ? res.locals.csrfToken.length : 'N/A');

    const users = await dbAll(`
      SELECT id, badge, username, role, hours, deliveries
      FROM users
      ORDER BY role, username
    `);

    const audits = await dbAll(`
      SELECT a.*, admins.username AS admin_name, targets.username AS target_name
      FROM admin_actions a
      LEFT JOIN users admins ON admins.id = a.admin_id
      LEFT JOIN users targets ON targets.id = a.target_id
      ORDER BY a.created_at DESC
      LIMIT 20
    `);

    res.render("admin", {
      user: req.session.user,
      users,
      audits,
      csrfToken: res.locals.csrfToken
    });
  } catch (e) {
    console.error('ERROR rendering admin page:', e && e.stack ? e.stack : e);
    console.error('DEBUG admin render: session user=', req.session.user, 'res.locals.csrfToken=', typeof res.locals.csrfToken !== 'undefined' ? res.locals.csrfToken : '(undefined)');
    throw e;
  }
});

// Admin: Add user (only executives may create executives)
app.post('/admin/users/add', requireAdmin, async (req, res) => {
  const { badge, username, password, role } = req.body;
  if (!badge || !username || !password) {
    req.session.flash = { type: 'error', message: 'Badge, username and password are required' };
    return res.redirect('/admin');
  }

  // Explicit checks by target role (safer - deny promotions to exec/manager unless assigner is executive, supervisors require manager+)
  console.log('DEBUG admin add: assigner=', req.session.user && req.session.user.role, 'desired=', role, 'canAssign=', canAssignRole(req.session.user && req.session.user.role, role));

  if (role === 'executive' && !hasRoleAtLeast(req.session.user.role, 'executive')) {
    req.session.flash = { type: 'error', message: 'Only executives can create executive users' };
    return res.redirect('/admin');
  }

  if (role === 'manager' && !hasRoleAtLeast(req.session.user.role, 'executive')) {
    req.session.flash = { type: 'error', message: 'Only executives can create manager users' };
    return res.redirect('/admin');
  }

  if (role === 'supervisor' && !hasRoleAtLeast(req.session.user.role, 'manager')) {
    req.session.flash = { type: 'error', message: 'Only managers or above can create supervisors' };
    return res.redirect('/admin');
  }

  // Fallback generic rule
  if (!canAssignRole(req.session.user.role, role)) {
    req.session.flash = { type: 'error', message: 'Insufficient privileges to assign that role' };
    return res.redirect('/admin');
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = await dbRun(`INSERT INTO users (badge, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)`, badge, username, hash, role, new Date().toISOString());

    // record admin action
    await recordAdminAction(req.session.user.id, 'create_user', info.lastID, { badge, username, role });

    console.log('DEBUG admin create_user: assigner=', req.session.user.role, 'created=', username, 'role=', role, 'id=', info.lastID);

    req.session.flash = { type: 'success', message: 'User created' };
  } catch (e) {
    req.session.flash = { type: 'error', message: 'Badge or username already exists' };
  }

  res.redirect('/admin');
});

// Admin: Edit user (form)
app.get('/admin/users/:id/edit', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const u = await dbGet('SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?', [id]);
  if (!u) return res.status(404).send('User not found');
  res.render('admin_edit', { user: u, currentUserRole: req.session.user.role, csrfToken: res.locals.csrfToken });
});

// Admin: Save edits (role changes to executive restricted to executives)
app.post('/admin/users/:id/edit', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).send('User not found');

  // Prevent non-executives from editing executive accounts
  if (user.role === 'executive' && !hasRoleAtLeast(req.session.user.role, 'executive')) {
    req.session.flash = { type: 'error', message: 'Only executives can edit executive accounts' };
    return res.redirect('/admin');
  }

  // Do not allow editing peers or superiors (unless you're an executive)
  if (ROLE_RANK[req.session.user.role] <= ROLE_RANK[user.role] && req.session.user.role !== 'executive') {
    req.session.flash = { type: 'error', message: 'Insufficient privileges to edit this user' };
    return res.redirect('/admin');
  }

  // Enforce role assignment rules for requested new role
  if (req.body.role && req.body.role !== user.role && !canAssignRole(req.session.user.role, req.body.role)) {
    req.session.flash = { type: 'error', message: 'Insufficient privileges to assign that role' };
    return res.redirect(`/admin/users/${id}/edit`);
  }

  const updates = [];
  const params = [];

  if (req.body.username && req.body.username !== user.username) {
    const exists = await dbGet('SELECT id FROM users WHERE username = ?', [req.body.username]);
    if (exists) {
      req.session.flash = { type: 'error', message: 'Username already taken' };
      return res.redirect(`/admin/users/${id}/edit`);
    }
    updates.push('username = ?'); params.push(req.body.username);
  }

  if (req.body.badge && String(req.body.badge) !== String(user.badge)) {
    const exists = await dbGet('SELECT id FROM users WHERE badge = ?', [req.body.badge]);
    if (exists) {
      req.session.flash = { type: 'error', message: 'Badge already taken' };
      return res.redirect(`/admin/users/${id}/edit`);
    }
    updates.push('badge = ?'); params.push(req.body.badge);
  }

  if (req.body.role && req.body.role !== user.role) {
    updates.push('role = ?'); params.push(req.body.role);
  }

  if (typeof req.body.hours !== 'undefined') {
    updates.push('hours = ?'); params.push(Number(req.body.hours) || 0);
  }

  if (typeof req.body.deliveries !== 'undefined') {
    updates.push('deliveries = ?'); params.push(Number(req.body.deliveries) || 0);
  }

  if (req.body.password) {
    updates.push('password = ?'); params.push(bcrypt.hashSync(req.body.password, 10));
  }

  if (updates.length) {
    params.push(id);
    await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, ...params);
    // record admin action
    await recordAdminAction(req.session.user.id, 'edit_user', id, { updates: updates });
    req.session.flash = { type: 'success', message: 'User updated' };
  } else {
    req.session.flash = { type: 'info', message: 'No changes made' };
  }

  // If admin edited themselves, refresh session
  if (req.session.user && Number(req.session.user.id) === Number(id)) {
    const updated = await dbGet('SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?', [id]);
    req.session.user = updated;
    res.locals.user = updated;
  }

  res.redirect('/admin');
});

// Admin: delete user
app.post('/admin/users/:id/delete', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).send('User not found');
  if (user.username === 'admin') { req.session.flash = { type: 'error', message: 'Cannot delete default admin' }; return res.redirect('/admin'); }

  // Prevent non-executives from deleting executives
  if (user.role === 'executive' && !hasRoleAtLeast(req.session.user.role, 'executive')) {
    req.session.flash = { type: 'error', message: 'Only executives can delete executive accounts' };
    return res.redirect('/admin');
  }

  await dbRun('DELETE FROM users WHERE id = ?', id);
  await recordAdminAction(req.session.user.id, 'delete_user', id, { username: user.username, role: user.role });
  req.session.flash = { type: 'success', message: 'User deleted' };
  res.redirect('/admin');
});

// =====================
// ROUTES — PROFILE
// =====================
app.get('/profile', requireLogin, async (req, res) => {
  const user = await dbGet("SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?", [req.session.user.id]);
  res.render('profile', { user, csrfToken: res.locals.csrfToken });
});

app.post('/profile', requireLogin, async (req, res) => {
  const user = await dbGet("SELECT * FROM users WHERE id = ?", [req.session.user.id]);

  // Check username collision if changed
  if (req.body.username && req.body.username !== user.username) {
    const exists = await dbGet('SELECT id FROM users WHERE username = ?', [req.body.username]);
    if (exists) {
      req.session.flash = { type: 'error', message: 'Username already taken' };
      return res.redirect('/profile');
    }
  }

  const updates = [];
  const params = [];

  if (req.body.username && req.body.username !== user.username) {
    updates.push('username = ?');
    params.push(req.body.username);
  }

  if (req.body.password) {
    updates.push('password = ?');
    params.push(bcrypt.hashSync(req.body.password, 10));
  }

  if (updates.length) {
    params.push(user.id);
    await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, ...params);
    req.session.flash = { type: 'success', message: 'Profile updated' };
  } else {
    req.session.flash = { type: 'info', message: 'No changes made' };
  }

  // Refresh session user
  const updatedUser = await dbGet("SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?", [user.id]);
  req.session.user = updatedUser;
  res.locals.user = updatedUser;

  res.redirect('/profile');
});

// =====================
// ROUTES — CONTACT
// =====================
app.get("/contact", requireLogin, (req, res) => {
  res.render("contact", { user: req.session.user, csrfToken: res.locals.csrfToken });
});

app.post("/contact", requireLogin, (req, res) => {
  console.log("CONTACT MESSAGE:", req.body);
  res.send("Message received (email hookup next)");
});

// =====================
// SERVER START
// =====================
const PORT = process.env.PORT || 3000;

// Lightweight health endpoint for PaaS health checks
app.get('/_health', (req, res) => res.sendStatus(200));

// Process-level error handlers to ensure crashes are visible in logs
process.on('uncaughtException', (err) => {
  console.error('uncaughtException', err);
  // Exit so platform can restart the process
  process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('unhandledRejection at', promise, 'reason:', reason);
  process.exit(1);
});

initDatabase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Node version: ${process.version}; NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch((e) => {
  console.error('Failed to initialize database, exiting', e);
  process.exit(1);
});
