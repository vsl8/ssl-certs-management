/**
 * SSL Cert Manager - Main Application JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // ─── Sidebar Toggle (Mobile) ───
    const sidebar = document.getElementById('sidebar');
    const sidebarOpen = document.getElementById('sidebarOpen');
    const sidebarClose = document.getElementById('sidebarClose');

    // Create overlay
    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);

    if (sidebarOpen) {
        sidebarOpen.addEventListener('click', function(e) {
            e.preventDefault();
            sidebar.classList.add('show');
            overlay.classList.add('show');
        });
    }

    if (sidebarClose) {
        sidebarClose.addEventListener('click', function(e) {
            e.preventDefault();
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        });
    }

    overlay.addEventListener('click', function() {
        sidebar.classList.remove('show');
        overlay.classList.remove('show');
    });

    // Close sidebar on resize to desktop
    window.addEventListener('resize', function() {
        if (window.innerWidth >= 992) {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        }
    });
});

/**
 * Show a toast notification using SweetAlert2.
 */
function showToast(icon, title) {
    Swal.fire({
        toast: true,
        position: 'top-end',
        icon: icon,
        title: title,
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true,
    });
}
