// auth-sync.js - Reusable Session & User Assignment Helper

document.addEventListener('DOMContentLoaded', () => {
    syncUserData();
});

function syncUserData() {
    // Read from the exact storage key your login uses ('portal_users')
    const userData = localStorage.getItem('portal_users');
    
    if (!userData) {
        // If not logged in, redirect to login page
        window.location.href = "index.html";
        return;
    }

    const user = JSON.parse(userData);
    
    // Support both 'employee_firstname' / 'employee_lastname' and standard 'firstname' / 'lastname'
    const firstName = user.employee_firstname || user.firstname || user.username || 'User';
    const lastName = user.employee_lastname || user.lastname || '';
    
    // 1. Determine Full Name format for header display
    const displayName = user.name || `${firstName} ${lastName}`.trim();
    
    // 2. Format Sidebar Footer as requested: <username> (<role>)
    const userRoleRaw = user.role || 'User';
    const usernameRoleText = `${user.username || firstName} (${userRoleRaw})`;

    // 3. Populate Sidebar Footer (Lower-Left)
    const sidebarUsername = document.getElementById('sidebar-username');
    if (sidebarUsername) {
        sidebarUsername.textContent = usernameRoleText;
    }

    // 4. Populate Header Top-Right Name
    const headerUserName = document.getElementById('header-user-name');
    if (headerUserName) {
        headerUserName.textContent = displayName;
    }

    // 5. Populate Header Top-Right Avatar Initials
    const headerUserInitials = document.getElementById('header-user-initials');
    if (headerUserInitials) {
        if (firstName && lastName && firstName !== 'User') {
            headerUserInitials.textContent = `${firstName[0]}`.toUpperCase() + `${lastName[0]}`.toUpperCase();
        } else {
            const nameParts = displayName.split(' ');
            if (nameParts.length > 1) {
                headerUserInitials.textContent = `${nameParts[0][0]}${nameParts[1][0]}`.toUpperCase();
            } else {
                headerUserInitials.textContent = nameParts[0].substring(0, 2).toUpperCase();
            }
        }
    }

    // 6. Role-Based Page Access Guards & Sidebar Link Visibility
    const userRole = userRoleRaw.trim();
    const currentPath = window.location.pathname;

    // Allowed roles definition
    const rosterAllowedRoles = ['IT', 'HR', 'IT-Admin', 'HR-Admin'];
    const userMgmtAllowedRoles = ['IT', 'IT-Admin', 'HR-Admin'];

    // Handle Provisioning Roster Link & Access Guard
    const rosterNavLink = document.getElementById('roster-nav-link');
    if (rosterAllowedRoles.includes(userRole)) {
        if (rosterNavLink) {
            rosterNavLink.classList.remove('hidden');
            rosterNavLink.style.display = 'flex';
        }
    } else {
        if (rosterNavLink) {
            rosterNavLink.classList.add('hidden');
            rosterNavLink.style.display = 'none';
        }
        if (currentPath.includes('provisioning_roster.html')) {
            alert('Access Denied: Your role does not have permission to access the Provisioning Roster.');
            window.location.href = 'dashboard.html';
        }
    }

    // Handle User Management Link & Access Guard
    const userMgmtNavLink = document.getElementById('usermgmt-nav-link');
    if (userMgmtAllowedRoles.includes(userRole)) {
        if (userMgmtNavLink) {
            userMgmtNavLink.classList.remove('hidden');
            userMgmtNavLink.style.display = 'flex';
        }
    } else {
        if (userMgmtNavLink) {
            userMgmtNavLink.classList.add('hidden');
            userMgmtNavLink.style.display = 'none';
        }
        if (currentPath.includes('user_management.html')) {
            alert('Access Denied: Your role does not have permission to access User Management.');
            window.location.href = 'dashboard.html';
        }
    }
}