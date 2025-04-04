const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key'; // Change this to a secure secret in production

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database('database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        createTables();
    }
});

function createTables() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS tours (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            duration INTEGER NOT NULL,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (provider_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tour_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tour_id) REFERENCES tours(id),
            FOREIGN KEY (client_id) REFERENCES users(id)
        )
    `);
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/signup', async (req, res) => {
    const { name, email, password, userType } = req.body;

    if (!name || !email || !password || !userType) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        // Check if user already exists
        db.get('SELECT email FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ message: 'Email already registered' });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            db.run(
                'INSERT INTO users (name, email, password, user_type) VALUES (?, ?, ?, ?)',
                [name, email, hashedPassword, userType],
                function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Error creating user' });
                    }
                    res.status(201).json({ message: 'User created successfully' });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password, userType } = req.body;

    if (!email || !password || !userType) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    db.get('SELECT * FROM users WHERE email = ? AND user_type = ?', [email, userType], async (err, user) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        try {
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { id: user.id, email: user.email, userType: user.user_type },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Remove password from user object
            const { password: _, ...userWithoutPassword } = user;

            res.json({
                user: userWithoutPassword,
                token
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error' });
        }
    });
});

// Admin routes
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all('SELECT id, name, email, user_type, created_at FROM users', (err, users) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(users);
    });
});

// Tour routes
app.get('/api/tours', (req, res) => {
    db.all(`
        SELECT t.*, u.name as provider_name 
        FROM tours t 
        JOIN users u ON t.provider_id = u.id 
        WHERE t.status = 'approved'
    `, (err, tours) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(tours);
    });
});

app.post('/api/tours', authenticateToken, (req, res) => {
    if (req.user.userType !== 'tour-provider') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { name, description, price, duration } = req.body;
    if (!name || !description || !price || !duration) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    db.run(
        'INSERT INTO tours (provider_id, name, description, price, duration, status) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, name, description, price, duration, 'pending'],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error creating tour' });
            }
            res.status(201).json({ message: 'Tour created successfully and waiting for admin approval' });
        }
    );
});

// Admin tour management routes
app.get('/api/admin/tours', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all(`
        SELECT t.*, u.name as provider_name, u.email as provider_email
        FROM tours t 
        JOIN users u ON t.provider_id = u.id
        WHERE t.status = 'pending'
    `, (err, tours) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(tours);
    });
});

app.put('/api/admin/tours/:id/status', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { status } = req.body;
    if (!status || !['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }

    db.run(
        'UPDATE tours SET status = ? WHERE id = ?',
        [status, req.params.id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error updating tour status' });
            }
            res.json({ message: `Tour ${status} successfully` });
        }
    );
});

// Provider-specific routes
app.get('/api/provider/tours', authenticateToken, (req, res) => {
    if (req.user.userType !== 'tour-provider') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all('SELECT * FROM tours WHERE provider_id = ?', [req.user.id], (err, tours) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(tours);
    });
});

app.get('/api/provider/bookings', authenticateToken, (req, res) => {
    if (req.user.userType !== 'tour-provider') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all(`
        SELECT b.*, t.name as tour_name, u.name as client_name
        FROM bookings b
        JOIN tours t ON b.tour_id = t.id
        JOIN users u ON b.client_id = u.id
        WHERE t.provider_id = ?
    `, [req.user.id], (err, bookings) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(bookings);
    });
});

// Booking routes
app.post('/api/bookings', authenticateToken, (req, res) => {
    if (req.user.userType !== 'client') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { tour_id } = req.body;
    if (!tour_id) {
        return res.status(400).json({ message: 'Tour ID is required' });
    }

    db.run(
        'INSERT INTO bookings (tour_id, client_id, status) VALUES (?, ?, ?)',
        [tour_id, req.user.id, 'pending'],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error creating booking' });
            }
            res.status(201).json({ message: 'Booking created successfully' });
        }
    );
});

app.put('/api/bookings/:id/cancel', authenticateToken, (req, res) => {
    if (req.user.userType !== 'client') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.run(
        'UPDATE bookings SET status = ? WHERE id = ? AND client_id = ?',
        ['cancelled', req.params.id, req.user.id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error cancelling booking' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Booking not found or unauthorized' });
            }
            res.json({ message: 'Booking cancelled successfully' });
        }
    );
});

app.get('/api/bookings', authenticateToken, (req, res) => {
    if (req.user.userType !== 'client') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all(`
        SELECT b.*, t.name as tour_name
        FROM bookings b
        JOIN tours t ON b.tour_id = t.id
        WHERE b.client_id = ?
    `, [req.user.id], (err, bookings) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(bookings);
    });
});

app.put('/api/bookings/:id/status', authenticateToken, (req, res) => {
    const { status } = req.body;
    if (!status) {
        return res.status(400).json({ message: 'Status is required' });
    }

    db.run(
        'UPDATE bookings SET status = ? WHERE id = ?',
        [status, req.params.id],
        function(err) {
            if (err) {
                return res.status(500).json({ message: 'Error updating booking status' });
            }
            res.json({ message: 'Booking status updated successfully' });
        }
    );
});

// Protected route example
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 