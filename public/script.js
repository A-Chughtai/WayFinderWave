document.addEventListener('DOMContentLoaded', () => {
    // Form toggle functionality
    const toggleButtons = document.querySelectorAll('.toggle-btn');
    const forms = document.querySelectorAll('.form');

    toggleButtons.forEach(button => {
        button.addEventListener('click', () => {
            const formType = button.dataset.form;
            
            // Update active button
            toggleButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Show corresponding form
            forms.forEach(form => {
                form.classList.remove('active');
                if (form.id === `${formType}-form`) {
                    form.classList.add('active');
                }
            });
        });
    });

    // Handle login form submission
    const loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const userType = document.getElementById('login-user-type').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password, userType })
            });

            const data = await response.json();
            
            if (response.ok) {
                // Store user data in localStorage
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('token', data.token);
                
                // Redirect based on user type
                switch (userType) {
                    case 'admin':
                        window.location.href = '/admin-dashboard.html';
                        break;
                    case 'tour-provider':
                        window.location.href = '/provider-dashboard.html';
                        break;
                    default:
                        window.location.href = '/client-dashboard.html';
                }
            } else {
                alert(data.message || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            alert('An error occurred during login');
        }
    });

    // Handle signup form submission
    const signupForm = document.getElementById('signup-form');
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const name = document.getElementById('signup-name').value;
        const email = document.getElementById('signup-email').value;
        const password = document.getElementById('signup-password').value;
        const userType = document.getElementById('signup-user-type').value;

        try {
            const response = await fetch('/api/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ name, email, password, userType })
            });

            const data = await response.json();
            
            if (response.ok) {
                alert('Signup successful! Please login.');
                // Switch to login form
                document.querySelector('[data-form="login"]').click();
            } else {
                alert(data.message || 'Signup failed');
            }
        } catch (error) {
            console.error('Signup error:', error);
            alert('An error occurred during signup');
        }
    });
}); 