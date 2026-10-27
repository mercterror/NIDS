import { Bell, PanelLeft, LogOut, UserRound } from 'lucide-react'

function Header({
  title = 'Overview',
  subtitle = 'Network security at a glance',
  apiStatus = 'checking',
  onToggleSidebar,
  onToggleNotifications,
  notificationCount = 0,
  user,
  onLogout,
}) {
  const statusLabels = {
    checking: 'Checking API',
    online: 'API Online',
    offline: 'API Offline',
  }

  return (
    <header className="top-header">
      <div className="header-left">
        <button
          type="button"
          className="icon-button sidebar-menu-button"
          onClick={onToggleSidebar}
          aria-label="Toggle sidebar"
          title="Toggle sidebar"
        >
          <PanelLeft size={19} />
        </button>

        <div className="header-page-info">
          <h1 className="header-title">{title}</h1>
          <p className="header-subtitle">{subtitle}</p>
        </div>
      </div>

      <div className="header-right">
        <div className={`api-status api-status-${apiStatus}`}>
          <span className="status-dot" />
          <span>{statusLabels[apiStatus] ?? 'API Status Unknown'}</span>
        </div>

        <button
          type="button"
          className="icon-button notification-button"
          onClick={onToggleNotifications}
          aria-label="Open notifications"
          title="Notifications"
        >
          <Bell size={19} />

          {notificationCount > 0 && (
            <span className="notification-badge">
              {notificationCount > 99 ? '99+' : notificationCount}
            </span>
          )}
        </button>

        <div className="header-user">
          <div className="header-user-avatar">
            <UserRound size={17} />
          </div>

          <div className="header-user-info">
            <span className="header-user-name">
              {user?.username || 'User'}
            </span>
            <span className="header-user-role">
              {user?.role || 'viewer'}
            </span>
          </div>

          <button
            type="button"
            className="icon-button header-logout-button"
            onClick={onLogout}
            aria-label="Log out"
            title="Log out"
          >
            <LogOut size={18} />
          </button>
        </div>
      </div>
    </header>
  )
}

export default Header