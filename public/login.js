
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const loginMessage = document.getElementById('login-message');
    const loginButton = document.getElementById('login-button');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        loginButton.disabled = true;
        loginMessage.textContent = 'Signing in...';

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    username,
                    password
                })
            });

            if (!response.ok) {
                loginMessage.textContent =
                    'Login failed. Check your username and password.';
                return;
            }

            loginMessage.textContent = 'Login successful! Redirecting...';

            // Redirect to the dashboard
            window.location.replace('/');

        } catch (error) {
            console.error('Login error:', error);

            loginMessage.textContent =
                'Unable to connect to the server. Please try again.';

        } finally {
            loginButton.disabled = false;
        }
    });
});

document.addEventListener('DOMContentLoaded', () => {
    const togglePassword = document.getElementById('toggle-password');
    const passwordInput = document.getElementById('password');

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', () => {
            const isHidden = passwordInput.type === 'password';

            passwordInput.type = isHidden ? 'text' : 'password';

            togglePassword.textContent = isHidden ? 'Hide' : 'Show';

            togglePassword.setAttribute(
                'aria-label',
                isHidden ? 'Hide password' : 'Show password'
            );

            togglePassword.setAttribute(
                'aria-pressed',
                String(isHidden)
            );
        });
    }
});
