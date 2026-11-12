
const $ = (id) => document.getElementById(id);

let users = [];
let currentUser = null;

// ========================================
// API REQUEST HELPER
// ========================================

async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
        credentials: 'same-origin',
        ...options
    });

    if (response.status === 401) {
        window.location.replace('/login.html');
        throw new Error('Session expired. Please log in again.');
    }

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.message ||
            data.error ||
            `Request failed (${response.status})`
        );
    }

    return data;
}

// ========================================
// UTILITIES
// ========================================

function addCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = String(value ?? '—');
    row.appendChild(cell);
    return cell;
}

function formatDate(value) {
    if (!value) return '—';

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? '—'
        : date.toLocaleDateString();
}

function createActionButton(label, handler) {
    const button = document.createElement('button');

    button.type = 'button';
    button.className = 'refresh-button';
    button.textContent = label;

    button.addEventListener('click', handler);

    return button;
}

function closeEditForm() {
    $('edit-user-section').hidden = true;
    $('edit-user-form').reset();
    $('edit-user-id').value = '';
    $('edit-user-message').textContent = '';
}

function closePasswordForm() {
    $('reset-password-section').hidden = true;
    $('reset-password-form').reset();
    $('reset-password-user-id').value = '';
    $('reset-password-message').textContent = '';
}

function showSection(sectionId) {
    const section = $(sectionId);
    section.hidden = false;

    section.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
}

function validatePassword(password) {
    if (password.length < 12) {
        throw new Error(
            'Password must contain at least 12 characters.'
        );
    }

    if (new TextEncoder().encode(password).length > 72) {
        throw new Error(
            'Password exceeds the 72-byte UTF-8 limit.'
        );
    }
}

// ========================================
// AUTHENTICATED USER
// ========================================

async function loadCurrentUser() {
    const data = await apiRequest('/api/auth/me');

    currentUser = data.user;

    if (currentUser.role !== 'admin') {
        window.location.replace('/index.html');

        throw new Error(
            'Administrator access required.'
        );
    }
}

// ========================================
// RENDER USER TABLE
// ========================================

function renderUsers() {
    const body = $('users-table-body');
    body.replaceChildren();

    const search = $('user-search')
        .value.toLowerCase().trim();

    const filtered = users.filter(user =>
        [
            user.full_name,
            user.username,
            user.email,
            user.role,
            user.status
        ].join(' ').toLowerCase().includes(search)
    );

    if (!filtered.length) {
        const row = document.createElement('tr');

        addCell(
            row,
            'No matching users found.'
        ).colSpan = 8;

        body.appendChild(row);
        return;
    }

    for (const user of filtered) {
        const row = document.createElement('tr');

        addCell(row, user.id);
        addCell(row, user.full_name);
        addCell(row, user.username);
        addCell(row, user.email);
        addCell(row, user.role);
        addCell(row, user.status);
        addCell(row, formatDate(user.created_at));

        const actionCell = document.createElement('td');

        actionCell.style.display = 'flex';
        actionCell.style.gap = '8px';
        actionCell.style.flexWrap = 'wrap';

        const editButton = createActionButton(
            'Edit',
            () => openEditForm(user.id)
        );

        actionCell.appendChild(editButton);

        // The backend does not allow an administrator
        // to reset their own password through this endpoint.
        const isCurrentUser =
            currentUser &&
            Number(currentUser.id) === Number(user.id);

        if (!isCurrentUser) {
            const resetButton = createActionButton(
                'Reset Password',
                () => openPasswordForm(user.id)
            );

            actionCell.appendChild(resetButton);
        }

        row.appendChild(actionCell);
        body.appendChild(row);
    }
}

// ========================================
// ACCOUNT METRICS
// ========================================

function updateMetrics() {
    $('total-users').textContent = users.length;

    $('total-admins').textContent =
        users.filter(user => user.role === 'admin').length;

    $('total-analysts').textContent =
        users.filter(user => user.role === 'analyst').length;

    $('total-viewers').textContent =
        users.filter(user => user.role === 'viewer').length;
}

// ========================================
// LOAD USERS
// ========================================

async function loadUsers() {
    const data = await apiRequest('/api/users');

    users = data.users || [];

    updateMetrics();
    renderUsers();

    $('last-updated').textContent =
        `Updated ${new Date().toLocaleTimeString()}`;

    $('system-status-text').textContent = 'Connected';
}

// ========================================
// CREATE USER
// ========================================

async function createUser(event) {
    event.preventDefault();

    const message = $('user-form-message');

    const button = event.currentTarget.querySelector(
        'button[type="submit"]'
    );

    button.disabled = true;
    message.textContent = 'Creating user...';

    try {
        const password = $('user-password').value;

        validatePassword(password);

        await apiRequest('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                full_name: $('user-full-name').value.trim(),
                username: $('user-username').value.trim(),
                email: $('user-email').value.trim(),
                password,
                role: $('user-role').value
            })
        });

        $('create-user-form').reset();

        message.textContent =
            'User created successfully.';

        await loadUsers();

    } catch (error) {
        message.textContent = error.message;

    } finally {
        button.disabled = false;
    }
}

// ========================================
// OPEN EDIT USER FORM
// ========================================

function openEditForm(id) {
    const user = users.find(
        item => Number(item.id) === Number(id)
    );

    if (!user) {
        alert('User not found. Refresh and try again.');
        return;
    }

    closePasswordForm();

    $('edit-user-id').value = user.id;
    $('edit-full-name').value = user.full_name;
    $('edit-username').value = user.username;
    $('edit-email').value = user.email;
    $('edit-role').value = user.role;
    $('edit-status').value = user.status;

    $('edit-user-title').textContent =
        `Edit User: ${user.username}`;

    $('edit-user-message').textContent = '';

    const isCurrentUser =
        currentUser &&
        Number(currentUser.id) === Number(user.id);

    // Prevent accidental self-demotion/deactivation.
    $('edit-role').disabled = isCurrentUser;
    $('edit-status').disabled = isCurrentUser;

    if (isCurrentUser) {
        $('edit-user-message').textContent =
            'You cannot change your own administrator role or deactivate your account.';
    }

    showSection('edit-user-section');
}

// ========================================
// SAVE USER CHANGES
// ========================================

async function saveUserChanges(event) {
    event.preventDefault();

    const id = Number($('edit-user-id').value);

    const message = $('edit-user-message');

    const button = event.currentTarget.querySelector(
        'button[type="submit"]'
    );

    const existingUser = users.find(
        user => Number(user.id) === id
    );

    if (!existingUser) {
        message.textContent = 'User not found. Refresh the page.';
        return;
    }

    button.disabled = true;
    message.textContent = 'Saving changes...';

    try {
        const isCurrentUser =
            currentUser &&
            Number(currentUser.id) === id;

        const role = isCurrentUser
            ? existingUser.role
            : $('edit-role').value;

        const status = isCurrentUser
            ? existingUser.status
            : $('edit-status').value;

        await apiRequest(`/api/users/${id}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                full_name: $('edit-full-name').value.trim(),
                username: $('edit-username').value.trim(),
                email: $('edit-email').value.trim(),
                role,
                status
            })
        });

        message.textContent =
            'User updated successfully.';

        await loadUsers();

        // Keep the updated form visible so the administrator
        // can see the success message.
    } catch (error) {
        message.textContent = error.message;

    } finally {
        button.disabled = false;
    }
}

// ========================================
// OPEN RESET PASSWORD FORM
// ========================================

function openPasswordForm(id) {
    const user = users.find(
        item => Number(item.id) === Number(id)
    );

    if (!user) {
        alert('User not found. Refresh and try again.');
        return;
    }

    const isCurrentUser =
        currentUser &&
        Number(currentUser.id) === Number(user.id);

    if (isCurrentUser) {
        alert(
            'You cannot reset your own password through this form.'
        );
        return;
    }

    closeEditForm();

    $('reset-password-user-id').value = user.id;

    $('reset-password-title').textContent =
        `Reset Password: ${user.username}`;

    $('reset-password-message').textContent = '';

    $('reset-new-password').value = '';
    $('reset-confirm-password').value = '';

    showSection('reset-password-section');
}

// ========================================
// RESET USER PASSWORD
// ========================================

async function resetUserPassword(event) {
    event.preventDefault();

    const id = Number(
        $('reset-password-user-id').value
    );

    const message = $('reset-password-message');

    const button = event.currentTarget.querySelector(
        'button[type="submit"]'
    );

    button.disabled = true;
    message.textContent = 'Resetting password...';

    try {
        const password = $('reset-new-password').value;
        const confirmation = $('reset-confirm-password').value;

        validatePassword(password);

        if (password !== confirmation) {
            throw new Error(
                'Passwords do not match.'
            );
        }

        await apiRequest(
            `/api/users/${id}/password`,
            {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ password })
            }
        );

        $('reset-new-password').value = '';
        $('reset-confirm-password').value = '';

        message.textContent =
            'Password reset successfully. Share the temporary password through a secure channel.';

        await loadUsers();

    } catch (error) {
        message.textContent = error.message;

    } finally {
        button.disabled = false;
    }
}

// ========================================
// REFRESH PAGE
// ========================================

async function refreshPage() {
    try {
        await loadUsers();

    } catch (error) {
        $('system-status-text').textContent =
            'Connection error';

        console.error('Failed to refresh users:', error);
    }
}

// ========================================
// LOGOUT
// ========================================

async function logout() {
    try {
        const response = await fetch(
            '/api/auth/logout',
            {
                method: 'POST',
                credentials: 'same-origin'
            }
        );

        if (!response.ok) {
            throw new Error('Sign out failed');
        }

        window.location.replace('/login.html');

    } catch (error) {
        alert(error.message);
    }
}

// ========================================
// INITIALIZE USER MANAGEMENT
// ========================================

document.addEventListener('DOMContentLoaded', async () => {
    $('user-search').addEventListener(
        'input',
        renderUsers
    );

    $('create-user-form').addEventListener(
        'submit',
        createUser
    );

    $('edit-user-form').addEventListener(
        'submit',
        saveUserChanges
    );

    $('reset-password-form').addEventListener(
        'submit',
        resetUserPassword
    );

    $('edit-user-cancel').addEventListener(
        'click',
        closeEditForm
    );

    $('reset-password-cancel').addEventListener(
        'click',
        closePasswordForm
    );

    $('refresh-btn').addEventListener(
        'click',
        refreshPage
    );

    $('logout-btn').addEventListener(
        'click',
        logout
    );

    try {
        await loadCurrentUser();
        await loadUsers();

    } catch (error) {
        console.error(
            'User Management initialization failed:',
            error
        );

        $('system-status-text').textContent =
            'Unable to initialize';
    }
});
