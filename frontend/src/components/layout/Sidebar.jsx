
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Monitor,
  Ban,
  ChartNoAxesCombined,
  Settings,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'

const navigationItems = [
  { label: 'Overview', path: '/', icon: LayoutDashboard },
  { label: 'Live Traffic', path: '/traffic', icon: Activity },
  { label: 'Alerts & Incidents', path: '/alerts', icon: ShieldAlert },
  { label: 'Devices', path: '/devices', icon: Monitor },
  { label: 'Blocked Entities', path: '/blocked', icon: Ban },
  { label: 'Analytics', path: '/analytics', icon: ChartNoAxesCombined },
  { label: 'Settings', path: '/settings', icon: Settings },
]

function Sidebar({ activePath = '/', collapsed = false, onToggle, onNavigate }) {
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <div className="sidebar-brand">
        <div className="brand-icon">
          <ShieldCheck size={23} />
        </div>

        {!collapsed && (
          <div className="brand-text">
            <span className="brand-name">NIDS</span>
            <span className="brand-subtitle">SECURITY CONSOLE</span>
          </div>
        )}
      </div>

      <div className="sidebar-section-label">
        {!collapsed && 'MONITORING'}
      </div>

      <nav className="sidebar-navigation" aria-label="Main navigation">
        {navigationItems.map(({ label, path, icon: Icon }) => (
          <button
            key={path}
            type="button"
            className={`nav-item ${activePath === path ? 'nav-item-active' : ''}`}
            onClick={() => onNavigate?.(path)}
            title={collapsed ? label : undefined}
            aria-current={activePath === path ? 'page' : undefined}
          >
            <Icon size={19} strokeWidth={1.8} />
            {!collapsed && <span>{label}</span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <button
          type="button"
          className="sidebar-toggle"
          onClick={onToggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
          {!collapsed && <span>Collapse sidebar</span>}
        </button>
      </div>
    </aside>
  )
}

export default Sidebar
