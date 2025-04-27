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

    // Check if capacity column exists, if not add it
    db.all("PRAGMA table_info(tours)", (err, rows) => {
        if (err) {
            console.error('Error checking table structure:', err);
            return;
        }
        
        const hasCapacityColumn = rows && rows.some(row => row.name === 'capacity');
        if (!hasCapacityColumn) {
            console.log('Adding capacity column to tours table...');
            db.run('ALTER TABLE tours ADD COLUMN capacity INTEGER NOT NULL DEFAULT 10', (err) => {
                if (err) {
                    console.error('Error adding capacity column:', err);
                } else {
                    console.log('Successfully added capacity column');
                }
            });
        }
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tour_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            payment_method TEXT DEFAULT 'cash',
            date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tour_id) REFERENCES tours(id),
            FOREIGN KEY (client_id) REFERENCES users(id)
        )
    `);

    // Check if payment_method column exists in bookings table, if not add it
    db.all("PRAGMA table_info(bookings)", (err, rows) => {
        if (err) {
            console.error('Error checking bookings table structure:', err);
            return;
        }
        
        if (!rows || !Array.isArray(rows)) {
            console.error('Invalid rows data:', rows);
            return;
        }

        const hasPaymentMethodColumn = rows.some(row => row.name === 'payment_method');
        if (!hasPaymentMethodColumn) {
            console.log('Adding payment_method column to bookings table...');
            db.run('ALTER TABLE bookings ADD COLUMN payment_method TEXT DEFAULT "cash"', (err) => {
                if (err) {
                    console.error('Error adding payment_method column:', err);
                } else {
                    console.log('Successfully added payment_method column');
                }
            });
        }
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL,
            client_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (booking_id) REFERENCES bookings(id),
            FOREIGN KEY (client_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
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

// Add logging middleware
function logAction(userId, action, details) {
    db.run(
        'INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
        [userId, action, details]
    );
}

// Modify tour creation to include better error handling
app.post('/api/tours', authenticateToken, (req, res) => {
    if (req.user.userType !== 'tour-provider') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { name, description, price, duration, capacity } = req.body;
    
    console.log('Received tour creation request:', {
        name,
        description,
        price,
        duration,
        capacity,
        provider_id: req.user.id
    });

    // Validate all required fields
    if (!name || !description || !price || !duration || !capacity) {
        console.log('Missing required fields:', {
            name: !name,
            description: !description,
            price: !price,
            duration: !duration,
            capacity: !capacity
        });
        return res.status(400).json({ 
            message: 'All fields are required',
            missing: {
                name: !name,
                description: !description,
                price: !price,
                duration: !duration,
                capacity: !capacity
            }
        });
    }

    // Validate numeric fields
    if (isNaN(price) || isNaN(duration) || isNaN(capacity)) {
        console.log('Invalid numeric fields:', {
            price: isNaN(price),
            duration: isNaN(duration),
            capacity: isNaN(capacity)
        });
        return res.status(400).json({ 
            message: 'Price, duration, and capacity must be numbers',
            invalid: {
                price: isNaN(price),
                duration: isNaN(duration),
                capacity: isNaN(capacity)
            }
        });
    }

    // Validate positive values
    if (price <= 0 || duration <= 0 || capacity <= 0) {
        console.log('Invalid positive values:', {
            price: price <= 0,
            duration: duration <= 0,
            capacity: capacity <= 0
        });
        return res.status(400).json({ 
            message: 'Price, duration, and capacity must be positive numbers',
            invalid: {
                price: price <= 0,
                duration: duration <= 0,
                capacity: capacity <= 0
            }
        });
    }

    const query = 'INSERT INTO tours (provider_id, name, description, price, duration, capacity, status) VALUES (?, ?, ?, ?, ?, ?, ?)';
    const params = [req.user.id, name, description, price, duration, capacity, 'pending'];

    console.log('Executing query:', query);
    console.log('With parameters:', params);

    db.run(query, params, function(err) {
        if (err) {
            console.error('Database error during tour creation:', err);
            return res.status(500).json({ 
                message: 'Error creating tour',
                error: err.message
            });
        }
        console.log('Tour created successfully with ID:', this.lastID);
        logAction(req.user.id, 'CREATE_TOUR', `Created tour: ${name} with capacity ${capacity}`);
        res.status(201).json({ message: 'Tour created successfully and waiting for admin approval' });
    });
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

// Modify tour deletion to include logging
app.delete('/api/provider/tours/:id', authenticateToken, (req, res) => {
    if (req.user.userType !== 'tour-provider') {
        return res.status(403).json({ message: 'Access denied' });
    }

    // First check if the tour belongs to the provider
    db.get('SELECT provider_id, name FROM tours WHERE id = ?', [req.params.id], (err, tour) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!tour) {
            return res.status(404).json({ message: 'Tour not found' });
        }
        if (tour.provider_id !== req.user.id) {
            return res.status(403).json({ message: 'You can only delete your own tours' });
        }

        // Check if there are any non-completed bookings for this tour
        db.get('SELECT COUNT(*) as count FROM bookings WHERE tour_id = ? AND status != ?', 
            [req.params.id, 'completed'], 
            (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error' });
                }
                if (result.count > 0) {
                    return res.status(400).json({ 
                        message: 'Cannot delete tour. There are active or pending bookings.' 
                    });
                }

                // Delete the tour
                db.run('DELETE FROM tours WHERE id = ?', [req.params.id], function(err) {
                    if (err) {
                        return res.status(500).json({ message: 'Error deleting tour' });
                    }
                    logAction(req.user.id, 'DELETE_TOUR', `Deleted tour: ${tour.name}`);
                    res.json({ message: 'Tour deleted successfully' });
                });
            }
        );
    });
});

// Booking routes
app.post('/api/bookings', authenticateToken, (req, res) => {
    if (req.user.userType !== 'client') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { tour_id, payment_method = 'cash' } = req.body;
    console.log('Received booking request:', { tour_id, payment_method, user_id: req.user.id });

    if (!tour_id) {
        return res.status(400).json({ message: 'Tour ID is required' });
    }

    // Validate payment method
    const validPaymentMethods = ['cash', 'credit'];
    if (!validPaymentMethods.includes(payment_method.toLowerCase())) {
        return res.status(400).json({ message: 'Invalid payment method. Please select either cash or credit card.' });
    }

    // Check if tour exists and has available capacity
    db.get(`
        SELECT t.capacity, t.name, t.price, COUNT(b.id) as current_bookings
        FROM tours t
        LEFT JOIN bookings b ON t.id = b.tour_id AND b.status != 'cancelled'
        WHERE t.id = ?
        GROUP BY t.id
    `, [tour_id], (err, result) => {
        if (err) {
            console.error('Database error when checking tour capacity:', err);
            return res.status(500).json({ message: 'Database error when checking tour capacity' });
        }
        if (!result) {
            console.log('Tour not found:', tour_id);
            return res.status(404).json({ message: 'Tour not found' });
        }
        if (result.current_bookings >= result.capacity) {
            console.log('Tour is fully booked:', { tour_id, current_bookings: result.current_bookings, capacity: result.capacity });
            return res.status(400).json({ message: 'Tour is fully booked' });
        }

        console.log('Creating booking with data:', {
            tour_id,
            client_id: req.user.id,
            status: 'pending',
            payment_method
        });

        // Create the booking
        db.run(
            'INSERT INTO bookings (tour_id, client_id, status, payment_method) VALUES (?, ?, ?, ?)',
            [tour_id, req.user.id, 'pending', payment_method],
            function(err) {
                if (err) {
                    console.error('Error creating booking:', err);
                    console.error('SQL Error details:', {
                        code: err.code,
                        message: err.message,
                        stack: err.stack
                    });
                    return res.status(500).json({ 
                        message: 'Error creating booking',
                        error: err.message
                    });
                }
                console.log('Booking created successfully:', {
                    booking_id: this.lastID,
                    tour_id,
                    client_id: req.user.id,
                    payment_method
                });
                logAction(req.user.id, 'BOOK_TOUR', `Booked tour: ${result.name} with payment method: ${payment_method}`);
                res.status(201).json({ 
                    message: 'Booking created successfully',
                    booking_id: this.lastID,
                    payment_method: payment_method,
                    price: result.price
                });
            }
        );
    });
});

app.put('/api/bookings/:id/cancel', authenticateToken, (req, res) => {
    if (req.user.userType !== 'client') {
        return res.status(403).json({ message: 'Access denied' });
    }

    // Get booking details before cancellation
    db.get(`
        SELECT b.*, t.name as tour_name
        FROM bookings b
        JOIN tours t ON b.tour_id = t.id
        WHERE b.id = ? AND b.client_id = ?
    `, [req.params.id, req.user.id], (err, booking) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!booking) {
            return res.status(404).json({ message: 'Booking not found' });
        }

        db.run(
            'UPDATE bookings SET status = ? WHERE id = ? AND client_id = ?',
            ['cancelled', req.params.id, req.user.id],
            function(err) {
                if (err) {
                    return res.status(500).json({ message: 'Error cancelling booking' });
                }
                logAction(req.user.id, 'CANCEL_BOOKING', `Cancelled booking for tour: ${booking.tour_name}`);
                res.json({ message: 'Booking cancelled successfully' });
            }
        );
    });
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

// Add admin logs endpoint
app.get('/api/admin/logs', authenticateToken, (req, res) => {
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    db.all(`
        SELECT l.*, u.name as user_name, u.user_type
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY l.created_at DESC
        LIMIT 100
    `, (err, logs) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(logs);
    });
});

// Add receipt endpoint
app.get('/api/bookings/:id/receipt', authenticateToken, (req, res) => {
    db.get(`
        SELECT b.*, t.name as tour_name, t.price, u.name as client_name
        FROM bookings b
        JOIN tours t ON b.tour_id = t.id
        JOIN users u ON b.client_id = u.id
        WHERE b.id = ? AND b.client_id = ?
    `, [req.params.id, req.user.id], (err, booking) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        if (!booking) {
            return res.status(404).json({ message: 'Booking not found' });
        }
        res.json(booking);
    });
});

// Add feedback endpoint
app.post('/api/bookings/:id/feedback', authenticateToken, (req, res) => {
    const { rating, comment } = req.body;
    
    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    // First check if the booking exists and belongs to the user
    db.get('SELECT * FROM bookings WHERE id = ? AND client_id = ?', 
        [req.params.id, req.user.id], (err, booking) => {
            if (err) {
                return res.status(500).json({ message: 'Database error' });
            }
            if (!booking) {
                return res.status(404).json({ message: 'Booking not found' });
            }

            // Check if feedback already exists
            db.get('SELECT * FROM feedback WHERE booking_id = ?', [req.params.id], (err, existingFeedback) => {
                if (err) {
                    return res.status(500).json({ message: 'Database error' });
                }
                if (existingFeedback) {
                    return res.status(400).json({ message: 'Feedback already submitted for this booking' });
                }

                // Insert new feedback
                db.run(
                    'INSERT INTO feedback (booking_id, client_id, rating, comment) VALUES (?, ?, ?, ?)',
                    [req.params.id, req.user.id, rating, comment],
                    function(err) {
                        if (err) {
                            return res.status(500).json({ message: 'Error submitting feedback' });
                        }
                        res.status(201).json({ message: 'Feedback submitted successfully' });
                    }
                );
            });
        });
});

// Get feedback for a tour
app.get('/api/tours/:id/feedback', (req, res) => {
    db.all(`
        SELECT f.*, u.name as client_name
        FROM feedback f
        JOIN bookings b ON f.booking_id = b.id
        JOIN users u ON f.client_id = u.id
        WHERE b.tour_id = ?
        ORDER BY f.created_at DESC
    `, [req.params.id], (err, feedback) => {
        if (err) {
            return res.status(500).json({ message: 'Database error' });
        }
        res.json(feedback);
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 