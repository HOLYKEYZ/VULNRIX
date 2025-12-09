/**
 * VULNRIX Command Palette
 * Ctrl+K to open, Escape to close
 */

class CommandPalette {
    constructor() {
        this.commands = [
            { id: 'new-osint-scan', label: 'New OSINT Scan', icon: 'fa-search', action: () => window.location.href = '/scan/new' },
            { id: 'new-code-scan', label: 'New Code Scan', icon: 'fa-code', action: () => window.location.href = '/vuln/' },
            { id: 'dashboard', label: 'Go to Dashboard', icon: 'fa-home', action: () => window.location.href = '/' },
            { id: 'scan-history', label: 'Scan History', icon: 'fa-history', action: () => window.location.href = '/history/' },
            { id: 'api-keys', label: 'Manage API Keys', icon: 'fa-key', action: () => window.location.href = '/accounts/settings/' },
            { id: 'docs', label: 'API Documentation', icon: 'fa-book', action: () => window.location.href = '/api/v1/docs' },
            { id: 'toggle-theme', label: 'Toggle Dark/Light Mode', icon: 'fa-moon', action: () => this.toggleTheme() },
            { id: 'logout', label: 'Logout', icon: 'fa-sign-out-alt', action: () => window.location.href = '/accounts/logout/' },
        ];
        this.filteredCommands = [...this.commands];
        this.selectedIndex = 0;
        this.isOpen = false;
        
        this.init();
    }
    
    init() {
        // Create overlay
        this.overlay = document.createElement('div');
        this.overlay.className = 'command-palette-overlay';
        this.overlay.innerHTML = `
            <div class="command-palette">
                <input type="text" class="command-palette__input" placeholder="Type a command... (Ctrl+K)" autocomplete="off">
                <div class="command-palette__results"></div>
            </div>
        `;
        document.body.appendChild(this.overlay);
        
        this.input = this.overlay.querySelector('.command-palette__input');
        this.results = this.overlay.querySelector('.command-palette__results');
        
        // Event listeners
        document.addEventListener('keydown', (e) => this.handleKeydown(e));
        this.input.addEventListener('input', () => this.filter());
        this.overlay.addEventListener('click', (e) => {
            if (e.target === this.overlay) this.close();
        });
        
        this.render();
    }
    
    handleKeydown(e) {
        // Ctrl+K or Cmd+K to open
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            this.toggle();
            return;
        }
        
        if (!this.isOpen) return;
        
        switch (e.key) {
            case 'Escape':
                this.close();
                break;
            case 'ArrowDown':
                e.preventDefault();
                this.selectedIndex = Math.min(this.selectedIndex + 1, this.filteredCommands.length - 1);
                this.render();
                break;
            case 'ArrowUp':
                e.preventDefault();
                this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
                this.render();
                break;
            case 'Enter':
                e.preventDefault();
                this.executeSelected();
                break;
        }
    }
    
    toggle() {
        this.isOpen ? this.close() : this.open();
    }
    
    open() {
        this.isOpen = true;
        this.overlay.classList.add('active');
        this.input.value = '';
        this.filter();
        this.input.focus();
    }
    
    close() {
        this.isOpen = false;
        this.overlay.classList.remove('active');
    }
    
    filter() {
        const query = this.input.value.toLowerCase().trim();
        
        if (!query) {
            this.filteredCommands = [...this.commands];
        } else {
            this.filteredCommands = this.commands.filter(cmd => 
                cmd.label.toLowerCase().includes(query) ||
                cmd.id.includes(query)
            );
        }
        
        this.selectedIndex = 0;
        this.render();
    }
    
    render() {
        this.results.innerHTML = this.filteredCommands.map((cmd, i) => `
            <div class="command-palette__item ${i === this.selectedIndex ? 'selected' : ''}" data-index="${i}">
                <i class="fas ${cmd.icon}"></i>
                <span>${cmd.label}</span>
            </div>
        `).join('');
        
        // Click handlers for items
        this.results.querySelectorAll('.command-palette__item').forEach(item => {
            item.addEventListener('click', () => {
                this.selectedIndex = parseInt(item.dataset.index);
                this.executeSelected();
            });
        });
        
        // Scroll selected into view
        const selectedEl = this.results.querySelector('.selected');
        if (selectedEl) {
            selectedEl.scrollIntoView({ block: 'nearest' });
        }
    }
    
    executeSelected() {
        const cmd = this.filteredCommands[this.selectedIndex];
        if (cmd) {
            this.close();
            cmd.action();
        }
    }
    
    toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('vulnrix-theme', next);
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.commandPalette = new CommandPalette();
    
    // Restore theme preference
    const savedTheme = localStorage.getItem('vulnrix-theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
});


/**
 * Animated Counter (CountUp effect)
 */
class AnimatedCounter {
    constructor(element, target, duration = 1000) {
        this.element = element;
        this.target = parseInt(target) || 0;
        this.duration = duration;
        this.start = 0;
        this.startTime = null;
    }
    
    animate(currentTime) {
        if (!this.startTime) this.startTime = currentTime;
        
        const elapsed = currentTime - this.startTime;
        const progress = Math.min(elapsed / this.duration, 1);
        
        // Easing function (ease-out)
        const easeOut = 1 - Math.pow(1 - progress, 3);
        
        const current = Math.floor(this.start + (this.target - this.start) * easeOut);
        this.element.textContent = current.toLocaleString();
        
        if (progress < 1) {
            requestAnimationFrame((t) => this.animate(t));
        }
    }
    
    run() {
        requestAnimationFrame((t) => this.animate(t));
    }
}

// Auto-animate counters with data-count attribute
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-count]').forEach(el => {
        const target = el.getAttribute('data-count');
        new AnimatedCounter(el, target).run();
    });
});


/**
 * Skeleton Loader Manager
 */
class SkeletonLoader {
    static show(container, type = 'card') {
        const templates = {
            card: '<div class="skeleton skeleton-card"></div>',
            text: '<div class="skeleton skeleton-title"></div><div class="skeleton skeleton-text"></div><div class="skeleton skeleton-text" style="width:80%"></div>',
            stat: '<div class="skeleton" style="height:60px;width:100%"></div>'
        };
        
        container.innerHTML = templates[type] || templates.card;
    }
    
    static hide(container) {
        container.querySelectorAll('.skeleton').forEach(el => el.remove());
    }
}

// Export for use
window.SkeletonLoader = SkeletonLoader;


/**
 * Toast Notifications
 */
class Toast {
    static show(message, type = 'info', duration = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        toast.innerHTML = `
            <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            <span>${message}</span>
        `;
        
        // Style the toast
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 20px;
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    
    static success(message) { this.show(message, 'success'); }
    static error(message) { this.show(message, 'error'); }
    static info(message) { this.show(message, 'info'); }
}

window.Toast = Toast;

// Add CSS for toast animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .toast--success { border-left: 3px solid #10b981; }
    .toast--error { border-left: 3px solid #ef4444; }
    .toast--info { border-left: 3px solid #3b82f6; }
`;
document.head.appendChild(style);
