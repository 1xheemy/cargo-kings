// =====================
// IMPORTS
// =====================
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const SQLite = require("better-sqlite3");

// =====================
// APP & DATABASE
// =====================
const app = express();
const db = new SQLite("database.db");

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
db.prepare(`
CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  action TEXT,
  target_id INTEGER,
  details TEXT,
  created_at TEXT
)
`).run();

function recordAdminAction(adminId, action, targetId, details) {
  try {
    db.prepare(`INSERT INTO admin_actions (admin_id, action, target_id, details, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(adminId, action, targetId || null, details ? JSON.stringify(details) : null, new Date().toISOString());
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

app.post("/login", (req, res) => {
  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(req.body.username);

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
});

// signup route consolidated (duplicate removed)

app.post("/signup", (req, res) => {
  const hash = bcrypt.hashSync(req.body.password, 10);

  // Public signups should always be regular truckers for safety
  const publicRole = 'trucker';

  try {
    db.prepare(`
      INSERT INTO users (badge, username, password, role, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(
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
app.get("/dashboard", requireLogin, (req, res) => {
  // Always fetch the latest user info
  const user = db.prepare(
    "SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?"
  ).get(req.session.user.id);

  let logs;
  if (user.role === 'trucker') {
    logs = db.prepare(`
      SELECT logs.*, users.username
      FROM logs
      JOIN users ON users.id = logs.user_id
      WHERE user_id = ?
      ORDER BY logs.created_at DESC
    `).all(user.id);
  } else {
    // non-trucker roles can see all logs
    logs = db.prepare(`
      SELECT logs.*, users.username
      FROM logs
      JOIN users ON users.id = logs.user_id
      ORDER BY logs.created_at DESC
    `).all();
  }

  // Debug: ensure CSRF and user are present for template rendering
  console.log('DEBUG /dashboard: req.session.user=', !!req.session.user ? { id: req.session.user.id, username: req.session.user.username, role: req.session.user.role } : null, 'res.locals.csrfToken defined=', typeof res.locals.csrfToken !== 'undefined');
  try { console.log('DEBUG /dashboard: req.csrfToken available=', typeof req.csrfToken === 'function'); } catch (e) { console.log('DEBUG /dashboard: req.csrfToken() threw'); }

  try {
    res.render("dashboard", {
      user,
      logs,
      csrfToken: res.locals.csrfToken
    });
  } catch (e) {
    console.error('ERROR rendering dashboard:', e && e.stack ? e.stack : e);
    // Re-throw so Express error handler can still produce the response (with stack in HTML) for tests
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

app.post("/log", requireLogin, (req, res) => {
  const user = req.session.user;
  const hoursToAdd = Number(req.body.hours) || 0;
  // Accept fuel as a category string (e.g., "below 20%", "20-50%", ...)
  const fuelCategory = req.body.fuel || req.body.fuel_level || '';
  const damage = req.body.damage || 'None';
  const plate = req.body.plate || '';
  const notes = req.body.notes || '';
  const deliveriesReported = Number(req.body.deliveries) || 0;
  const deliveriesToAdd = deliveriesReported > 0 ? deliveriesReported : 1; // default to 1 to preserve previous behaviour

  db.prepare(`
    INSERT INTO logs (user_id, vehicle, plate, deliveries, damage, fuel, insurance, notes, created_at, hours)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
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

  db.prepare(`
    UPDATE users
    SET hours = hours + ?, deliveries = deliveries + ?
    WHERE id = ?
  `).run(
    hoursToAdd,
    deliveriesToAdd,
    user.id
  );

  // Refresh session user with latest stats
  const updatedUser = db.prepare(
    "SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?"
  ).get(user.id);
  req.session.user = updatedUser;
  res.locals.user = updatedUser;

  res.redirect("/dashboard");
});

app.post('/logs/:id/delete', requireLogin, (req, res) => {
  const id = req.params.id;
  const log = db.prepare('SELECT * FROM logs WHERE id = ?').get(id);
  if (!log) return res.status(404).send('Log not found');

  // Only owner or non-trucker roles can delete
  if (log.user_id !== req.session.user.id && req.session.user.role === 'trucker') {
    return res.status(403).render('403');
  }

  db.prepare('DELETE FROM logs WHERE id = ?').run(id);

  // Adjust user's totals if possible
  if (log.user_id) {
    db.prepare('UPDATE users SET hours = hours - ?, deliveries = deliveries - 1 WHERE id = ?').run(log.hours || 0, log.user_id);

    if (log.user_id === req.session.user.id) {
      // Refresh session user
      const updatedUser = db.prepare(
        "SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?"
      ).get(log.user_id);
      req.session.user = updatedUser;
      res.locals.user = updatedUser;
    }
  }

  res.redirect('/dashboard');
});

// =====================
// ROUTES — ADMIN PANEL
// =====================
app.get("/admin", requireAdmin, (req, res) => {
  console.log('ADMIN GET: session user=', req.session.user && req.session.user.role, 'cookies=', req.headers.cookie);
  console.log('ADMIN GET: res.locals.csrfToken defined=', typeof res.locals.csrfToken !== 'undefined', 'value length=', typeof res.locals.csrfToken === 'string' ? res.locals.csrfToken.length : 'N/A');

  const users = db.prepare(`
    SELECT id, badge, username, role, hours, deliveries
    FROM users
    ORDER BY role, username
  `).all();

  const audits = db.prepare(`
    SELECT a.*, admins.username AS admin_name, targets.username AS target_name
    FROM admin_actions a
    LEFT JOIN users admins ON admins.id = a.admin_id
    LEFT JOIN users targets ON targets.id = a.target_id
    ORDER BY a.created_at DESC
    LIMIT 20
  `).all();

  try {
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
app.post('/admin/users/add', requireAdmin, (req, res) => {
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
    const info = db.prepare(`INSERT INTO users (badge, username, password, role, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(badge, username, hash, role, new Date().toISOString());

    // record admin action
    recordAdminAction(req.session.user.id, 'create_user', info.lastInsertRowid, { badge, username, role });

    console.log('DEBUG admin create_user: assigner=', req.session.user.role, 'created=', username, 'role=', role, 'id=', info.lastInsertRowid);

    req.session.flash = { type: 'success', message: 'User created' };
  } catch (e) {
    req.session.flash = { type: 'error', message: 'Badge or username already exists' };
  }

  res.redirect('/admin');
});

// Admin: Edit user (form)
app.get('/admin/users/:id/edit', requireAdmin, (req, res) => {
  const id = req.params.id;
  const u = db.prepare('SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?').get(id);
  if (!u) return res.status(404).send('User not found');
  res.render('admin_edit', { user: u, currentUserRole: req.session.user.role, csrfToken: res.locals.csrfToken });
});

// Admin: Save edits (role changes to executive restricted to executives)
app.post('/admin/users/:id/edit', requireAdmin, (req, res) => {
  const id = req.params.id;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
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
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(req.body.username);
    if (exists) {
      req.session.flash = { type: 'error', message: 'Username already taken' };
      return res.redirect(`/admin/users/${id}/edit`);
    }
    updates.push('username = ?'); params.push(req.body.username);
  }

  if (req.body.badge && String(req.body.badge) !== String(user.badge)) {
    const exists = db.prepare('SELECT id FROM users WHERE badge = ?').get(req.body.badge);
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
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    // record admin action
    recordAdminAction(req.session.user.id, 'edit_user', id, { updates: updates });
    req.session.flash = { type: 'success', message: 'User updated' };
  } else {
    req.session.flash = { type: 'info', message: 'No changes made' };
  }

  // If admin edited themselves, refresh session
  if (req.session.user && Number(req.session.user.id) === Number(id)) {
    const updated = db.prepare('SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?').get(id);
    req.session.user = updated;
    res.locals.user = updated;
  }

  res.redirect('/admin');
});

// Admin: delete user
app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
  const id = req.params.id;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).send('User not found');
  if (user.username === 'admin') { req.session.flash = { type: 'error', message: 'Cannot delete default admin' }; return res.redirect('/admin'); }

  // Prevent non-executives from deleting executives
  if (user.role === 'executive' && !hasRoleAtLeast(req.session.user.role, 'executive')) {
    req.session.flash = { type: 'error', message: 'Only executives can delete executive accounts' };
    return res.redirect('/admin');
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  recordAdminAction(req.session.user.id, 'delete_user', id, { username: user.username, role: user.role });
  req.session.flash = { type: 'success', message: 'User deleted' };
  res.redirect('/admin');
});

// =====================
// ROUTES — PROFILE
// =====================
app.get('/profile', requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?"
  ).get(req.session.user.id);
  res.render('profile', { user, csrfToken: res.locals.csrfToken });
});

app.post('/profile', requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT * FROM users WHERE id = ?"
  ).get(req.session.user.id);

  // Check username collision if changed
  if (req.body.username && req.body.username !== user.username) {
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(req.body.username);
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
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    req.session.flash = { type: 'success', message: 'Profile updated' };
  } else {
    req.session.flash = { type: 'info', message: 'No changes made' };
  }

  // Refresh session user
  const updatedUser = db.prepare(
    "SELECT id, badge, username, role, hours, deliveries FROM users WHERE id = ?"
  ).get(user.id);
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
app.listen(3000, () => {
  console.log("Cargo King running at http://localhost:3000");
});
