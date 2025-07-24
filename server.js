// server.js - Complete DNS Management Backend Server with Frontend
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const dbPath = path.join(__dirname, 'dns_management.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      subscription TEXT DEFAULT 'basic',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Domains table
  db.run(`
    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      UNIQUE(user_id, name)
    )
  `);

  // DNS Records table
  db.run(`
    CREATE TABLE IF NOT EXISTS dns_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      name TEXT NOT NULL,
      value TEXT NOT NULL,
      ttl INTEGER DEFAULT 3600,
      site TEXT DEFAULT 'SITE A',
      status TEXT DEFAULT 'ACTIVE',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
    )
  `);

  // Create default admin user (password: admin123)
  const defaultPassword = bcrypt.hashSync('admin123', 10);
  db.run(`
    INSERT OR IGNORE INTO users (username, password_hash, subscription) 
    VALUES ('admin@destek.com', ?, 'premium')
  `, [defaultPassword]);

  // Create demo user (password: demo123)
  const demoPassword = bcrypt.hashSync('demo123', 10);
  db.run(`
    INSERT OR IGNORE INTO users (username, password_hash, subscription) 
    VALUES ('demo@destek.com', ?, 'basic')
  `, [demoPassword]);
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Utility function to update timestamp
const updateTimestamp = (table, id) => {
  db.run(`UPDATE ${table} SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [id]);
};

// AUTHENTICATION ROUTES

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { 
          id: user.id, 
          username: user.username, 
          subscription: user.subscription 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          subscription: user.subscription
        }
      });
    }
  );
});

// Get current user info
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, subscription, created_at FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(user);
    }
  );
});

// DOMAIN ROUTES

// Get all domains for authenticated user
app.get('/api/domains', authenticateToken, (req, res) => {
  db.all(
    `SELECT d.*, COUNT(dr.id) as record_count 
     FROM domains d 
     LEFT JOIN dns_records dr ON d.id = dr.domain_id 
     WHERE d.user_id = ? 
     GROUP BY d.id 
     ORDER BY d.created_at DESC`,
    [req.user.id],
    (err, domains) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(domains);
    }
  );
});

// Add new domain
app.post('/api/domains', authenticateToken, (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Domain name is required' });
  }

  // Basic domain validation
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
  if (!domainRegex.test(name)) {
    return res.status(400).json({ error: 'Invalid domain name format' });
  }

  db.run(
    'INSERT INTO domains (user_id, name) VALUES (?, ?)',
    [req.user.id, name.toLowerCase()],
    function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Domain already exists' });
        }
        return res.status(500).json({ error: 'Database error' });
      }

      db.get(
        'SELECT * FROM domains WHERE id = ?',
        [this.lastID],
        (err, domain) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }
          res.status(201).json(domain);
        }
      );
    }
  );
});

// Delete domain
app.delete('/api/domains/:id', authenticateToken, (req, res) => {
  const domainId = req.params.id;

  // First check if domain belongs to user
  db.get(
    'SELECT * FROM domains WHERE id = ? AND user_id = ?',
    [domainId, req.user.id],
    (err, domain) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!domain) {
        return res.status(404).json({ error: 'Domain not found' });
      }

      // Delete domain (DNS records will be deleted due to CASCADE)
      db.run(
        'DELETE FROM domains WHERE id = ?',
        [domainId],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }
          res.json({ message: 'Domain deleted successfully' });
        }
      );
    }
  );
});

// DNS RECORDS ROUTES

// Get DNS records for a domain
app.get('/api/domains/:id/records', authenticateToken, (req, res) => {
  const domainId = req.params.id;

  // First verify domain belongs to user
  db.get(
    'SELECT * FROM domains WHERE id = ? AND user_id = ?',
    [domainId, req.user.id],
    (err, domain) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!domain) {
        return res.status(404).json({ error: 'Domain not found' });
      }

      // Get DNS records
      db.all(
        'SELECT * FROM dns_records WHERE domain_id = ? ORDER BY created_at DESC',
        [domainId],
        (err, records) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }
          res.json({
            domain: domain,
            records: records
          });
        }
      );
    }
  );
});

// Add DNS record
app.post('/api/domains/:id/records', authenticateToken, (req, res) => {
  const domainId = req.params.id;
  const { type, name, value, ttl, site, status } = req.body;

  // Validate required fields
  if (!type || !name || !value) {
    return res.status(400).json({ error: 'Type, name, and value are required' });
  }

  // Validate DNS record type
  const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV'];
  if (!validTypes.includes(type.toUpperCase())) {
    return res.status(400).json({ error: 'Invalid DNS record type' });
  }

  // First verify domain belongs to user
  db.get(
    'SELECT * FROM domains WHERE id = ? AND user_id = ?',
    [domainId, req.user.id],
    (err, domain) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!domain) {
        return res.status(404).json({ error: 'Domain not found' });
      }

      // Add DNS record
      db.run(
        `INSERT INTO dns_records (domain_id, type, name, value, ttl, site, status) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          domainId,
          type.toUpperCase(),
          name,
          value,
          ttl || 3600,
          site || 'SITE A',
          status || 'ACTIVE'
        ],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          // Update domain timestamp
          updateTimestamp('domains', domainId);

          // Return the created record
          db.get(
            'SELECT * FROM dns_records WHERE id = ?',
            [this.lastID],
            (err, record) => {
              if (err) {
                return res.status(500).json({ error: 'Database error' });
              }
              res.status(201).json(record);
            }
          );
        }
      );
    }
  );
});

// Update DNS record
app.put('/api/domains/:domainId/records/:recordId', authenticateToken, (req, res) => {
  const { domainId, recordId } = req.params;
  const { type, name, value, ttl, site, status } = req.body;

  // First verify domain belongs to user and record exists
  db.get(
    `SELECT dr.*, d.user_id FROM dns_records dr 
     JOIN domains d ON dr.domain_id = d.id 
     WHERE dr.id = ? AND dr.domain_id = ? AND d.user_id = ?`,
    [recordId, domainId, req.user.id],
    (err, record) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!record) {
        return res.status(404).json({ error: 'DNS record not found' });
      }

      // Update DNS record
      db.run(
        `UPDATE dns_records 
         SET type = ?, name = ?, value = ?, ttl = ?, site = ?, status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [
          type || record.type,
          name || record.name,
          value || record.value,
          ttl || record.ttl,
          site || record.site,
          status || record.status,
          recordId
        ],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          // Update domain timestamp
          updateTimestamp('domains', domainId);

          // Return updated record
          db.get(
            'SELECT * FROM dns_records WHERE id = ?',
            [recordId],
            (err, updatedRecord) => {
              if (err) {
                return res.status(500).json({ error: 'Database error' });
              }
              res.json(updatedRecord);
            }
          );
        }
      );
    }
  );
});

// Delete DNS record
app.delete('/api/domains/:domainId/records/:recordId', authenticateToken, (req, res) => {
  const { domainId, recordId } = req.params;

  // First verify domain belongs to user and record exists
  db.get(
    `SELECT dr.*, d.user_id FROM dns_records dr 
     JOIN domains d ON dr.domain_id = d.id 
     WHERE dr.id = ? AND dr.domain_id = ? AND d.user_id = ?`,
    [recordId, domainId, req.user.id],
    (err, record) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!record) {
        return res.status(404).json({ error: 'DNS record not found' });
      }

      // Delete DNS record
      db.run(
        'DELETE FROM dns_records WHERE id = ?',
        [recordId],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          // Update domain timestamp
          updateTimestamp('domains', domainId);

          res.json({ message: 'DNS record deleted successfully' });
        }
      );
    }
  );
});

// IMPORT/EXPORT ROUTES

// Export DNS records for a domain
app.get('/api/domains/:id/export', authenticateToken, (req, res) => {
  const domainId = req.params.id;

  // First verify domain belongs to user
  db.get(
    'SELECT * FROM domains WHERE id = ? AND user_id = ?',
    [domainId, req.user.id],
    (err, domain) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!domain) {
        return res.status(404).json({ error: 'Domain not found' });
      }

      // Get DNS records
      db.all(
        'SELECT type, name, value, ttl, site, status FROM dns_records WHERE domain_id = ?',
        [domainId],
        (err, records) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }

          // Convert to CSV format
          const csvHeader = 'Type,Name,Value,TTL,Site,Status\n';
          const csvRows = records.map(record => 
            `${record.type},${record.name},${record.value},${record.ttl},${record.site},${record.status}`
          ).join('\n');

          res.setHeader('Content-Type', 'text/csv');
          res.setHeader('Content-Disposition', `attachment; filename="${domain.name}_dns_records.csv"`);
          res.send(csvHeader + csvRows);
        }
      );
    }
  );
});

// Import DNS records for a domain
app.post('/api/domains/:id/import', authenticateToken, (req, res) => {
  const domainId = req.params.id;
  const { records } = req.body;

  if (!records || !Array.isArray(records)) {
    return res.status(400).json({ error: 'Records array is required' });
  }

  // First verify domain belongs to user
  db.get(
    'SELECT * FROM domains WHERE id = ? AND user_id = ?',
    [domainId, req.user.id],
    (err, domain) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!domain) {
        return res.status(404).json({ error: 'Domain not found' });
      }

      // Insert records in a transaction
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        let insertCount = 0;
        let errors = [];

        const insertPromises = records.map((record, index) => {
          return new Promise((resolve) => {
            db.run(
              `INSERT INTO dns_records (domain_id, type, name, value, ttl, site, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?)`,
              [
                domainId,
                record.type?.toUpperCase() || 'A',
                record.name || '@',
                record.value || record.ip || '',
                record.ttl || 3600,
                record.site || 'SITE A',
                record.status || 'ACTIVE'
              ],
              function(err) {
                if (err) {
                  errors.push(`Record ${index + 1}: ${err.message}`);
                } else {
                  insertCount++;
                }
                resolve();
              }
            );
          });
        });

        Promise.all(insertPromises).then(() => {
          if (errors.length > 0) {
            db.run('ROLLBACK');
            res.status(400).json({ 
              error: 'Import failed', 
              details: errors 
            });
          } else {
            db.run('COMMIT');
            updateTimestamp('domains', domainId);
            res.json({ 
              message: `Successfully imported ${insertCount} DNS records`,
              imported: insertCount 
            });
          }
        });
      });
    }
  );
});

// ADMIN ROUTES (for creating users)

// Create new user (admin only)
app.post('/api/admin/users', authenticateToken, (req, res) => {
  // Check if user is admin
  if (req.user.subscription !== 'premium' && req.user.username !== 'admin@destek.com') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { username, password, subscription } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  db.run(
    'INSERT INTO users (username, password_hash, subscription) VALUES (?, ?, ?)',
    [username, passwordHash, subscription || 'basic'],
    function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'Database error' });
      }

      res.status(201).json({
        id: this.lastID,
        username: username,
        subscription: subscription || 'basic',
        message: 'User created successfully'
      });
    }
  );
});

// Serve the frontend for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 DESTEK DNS Management Server running on port ${PORT}`);
  console.log(`🌐 Frontend available at: http://localhost:${PORT}`);
  console.log(`📊 Admin login: admin@destek.com / admin123`);
  console.log(`🧪 Demo login: demo@destek.com / demo123`);
  console.log(`💾 Database: ${dbPath}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('✅ Database connection closed.');
    }
    process.exit(0);
  });
});