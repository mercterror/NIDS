
import { BrowserRouter, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import {
  Activity,
  ShieldAlert,
  Monitor,
  Gauge,
} from 'lucide-react'

import Login from './pages/Login'
import {
  getAccessToken,
  getProfile,
  logout,
  clearAccessToken,
} from './services/api'

import { checkApiStatus, getDashboardStats } from './services/api'
import Sidebar from './components/layout/Sidebar'
import Header from './components/layout/Header'
import MetricCard from './components/common/MetricCard'
import ProtocolChart from './components/common/ProtocolChart'
import TrafficChart from './components/common/TrafficChart'
import RecentTraffic from './components/common/RecentTraffic'
import LiveTraffic from './pages/LiveTraffic'
import Alerts from './pages/Alerts'
import Devices from './pages/Devices'
import BlockedEntities from './pages/BlockedEntities'
import Analytics from './pages/Analytics'
import Settings from './pages/Settings'

const pageDetails = {
  '/': {
    title: 'Overview',
    subtitle: 'Network security at a glance',
  },
  '/traffic': {
    title: 'Live Traffic',
    subtitle: 'Inspect observed network traffic',
  },
  '/alerts': {
    title: 'Alerts & Incidents',
    subtitle: 'Review detected security threats',
  },
  '/devices': {
    title: 'Devices',
    subtitle: 'Explore observed network devices',
  },
  '/blocked': {
    title: 'Blocked Entities',
    subtitle: 'Review blocked IP and MAC addresses',
  },
  '/analytics': {
    title: 'Analytics',
    subtitle: 'Analyze network activity and threats',
  },
  '/settings': {
    title: 'Settings',
    subtitle: 'Manage application preferences',
  },
}

function DashboardLayout({ user, onLogout }) {
  const location = useLocation()
  const navigate = useNavigate()

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [apiStatus, setApiStatus] = useState('checking')
  const [stats, setStats] = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)
  const [statsError, setStatsError] = useState('')

  useEffect(() => {
    let isMounted = true

    const updateApiStatus = async () => {
      const status = await checkApiStatus()

      if (isMounted) {
        setApiStatus(status)
      }
    }

    updateApiStatus()

    const intervalId = setInterval(updateApiStatus, 10000)

    return () => {
      isMounted = false
      clearInterval(intervalId)
    }
  }, [])

  useEffect(() => {
    let isMounted = true

    const loadStats = async () => {
      try {
        const data = await getDashboardStats()

        if (isMounted) {
          setStats(data)
          setStatsError('')
        }
      } catch (error) {
        if (isMounted) {
          setStatsError('Unable to load dashboard statistics.')
        }
      } finally {
        if (isMounted) {
          setStatsLoading(false)
        }
      }
    }

    loadStats()

    const intervalId = setInterval(loadStats, 10000)

    return () => {
      isMounted = false
      clearInterval(intervalId)
    }
  }, [])

  const activePath = pageDetails[location.pathname]
    ? location.pathname
    : '/'

  const currentPage = pageDetails[activePath]

  const isOverview = activePath === '/'

  const metricCards = [
    {
      title: 'Traffic Records',
      value: stats?.total_packets,
      description: 'Average score of recorded attacks',
      icon: Activity,
      accent: 'cyan',
    },
    {
      title: 'Detected Attacks',
      value: stats?.total_attacks,
      description: 'Recorded attack events',
      icon: ShieldAlert,
      accent: 'red',
    },
    {
      title: 'Observed Devices',
      value: stats?.connected_devices,
      description: 'Devices recorded by the backend',
      icon: Monitor,
      accent: 'blue',
    },
    {
      title: 'Threat Score',
      value: stats?.threat_score,
      description: 'Average score of recorded attacks',
      icon: Gauge,
      accent: 'amber',
    },
  ]

  return (
    <div className="app-shell">
      <Sidebar
        activePath={activePath}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((previous) => !previous)}
        onNavigate={(path) => {
          navigate(path)
          setNotificationsOpen(false)
        }}
      />

      <main
        className={`app-main ${
          sidebarCollapsed ? 'app-main-collapsed' : ''
        }`}
      >
        <Header
        user={user}
        onLogout={onLogout}
          title={currentPage.title}
          subtitle={currentPage.subtitle}
          apiStatus={apiStatus}
          notificationCount={0}
          onToggleSidebar={() =>
            setSidebarCollapsed((previous) => !previous)
          }
          onToggleNotifications={() =>
            setNotificationsOpen((previous) => !previous)
          }
        />

        <section className="app-content">
          {notificationsOpen && (
            <div className="notification-panel">
              <h2>Notifications</h2>
              <p>No notifications are available yet.</p>
              <button
                type="button"
                className="notification-close"
                onClick={() => setNotificationsOpen(false)}
              >
                Close
              </button>
            </div>
          )}

          {isOverview ? (
            <div className="overview-content">
              {statsError && (
                <div className="dashboard-error" role="alert">
                  {statsError}
                </div>
              )}

              <div className="metrics-grid">
                {metricCards.map((metric) => (
                  <MetricCard
                    key={metric.title}
                    {...metric}
                    loading={statsLoading}
                  />
                ))}
              </div>
                <div className="overview-charts">
                  <TrafficChart />
                  <ProtocolChart />
                </div>

                <RecentTraffic />
            </div>
              ) : activePath === '/traffic' ? (
              <LiveTraffic />
              ) : activePath === '/alerts' ? (
                <Alerts />
              ) : activePath === '/devices' ? (
                <Devices />
              ) : activePath === '/blocked' ? (
                <BlockedEntities />
              ) : activePath === '/analytics' ? (
                <Analytics />
              ) : activePath === '/settings' ? (
                <Settings />
              ) : (
                <div className="page-placeholder">
                  <div className="placeholder-icon">N</div>
                  <h2>{currentPage.title}</h2>
                  <p>
                    This section will display real data from your NIDS backend.
                  </p>
                </div>
              )}
        </section>
      </main>
    </div>
  )
}

function App() {
  const [user, setUser] = useState(null)
  const [checkingAuth, setCheckingAuth] = useState(true)

  useEffect(() => {
    let active = true

    async function checkSession() {
      if (!getAccessToken()) {
        setCheckingAuth(false)
        return
      }

      try {
        const profile = await getProfile()

        if (active) {
          setUser(profile)
        }
      } catch {
        clearAccessToken()
      } finally {
        if (active) {
          setCheckingAuth(false)
        }
      }
    }

    checkSession()

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    function handleUnauthorized() {
      setUser(null)
    }

    window.addEventListener('nids:unauthorized', handleUnauthorized)

    return () => {
      window.removeEventListener(
        'nids:unauthorized',
        handleUnauthorized
      )
    }
  }, [])

  async function handleLogout() {
    try {
      await logout()
    } finally {
      setUser(null)
    }
  }

  if (checkingAuth) {
    return (
      <div className="auth-loading">
        Checking authentication...
      </div>
    )
  }

  if (!user) {
    return (
      <BrowserRouter>
        <Login onLogin={setUser} />
      </BrowserRouter>
    )
  }

  return (
  <BrowserRouter>
    <DashboardLayout user={user} onLogout={handleLogout} />
  </BrowserRouter>
)
}

export default App
