import { useEffect, useState } from 'react'
import {
  Activity,
  RefreshCw,
  ShieldAlert,
  ChartNoAxesCombined,
} from 'lucide-react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts'

import { apiRequest } from '../services/api'

const CHART_COLORS = [
  '#83c4d7',
  '#83c9a5',
  '#e2b66e',
  '#d98d8d',
  '#a9a0df',
]

function Analytics() {
  const [traffic, setTraffic] = useState([])
  const [protocols, setProtocols] = useState({})
  const [attacks, setAttacks] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')

  async function loadAnalytics(isManual = false) {
    if (isManual) {
      setRefreshing(true)
    }

    try {
      setError('')

      // All requests use the shared service, which attaches the JWT.
      const [trafficData, protocolData, attackData] = await Promise.all([
        apiRequest('/api/traffic'),
        apiRequest('/api/protocols'),
        apiRequest('/api/attacks'),
      ])

      setTraffic(Array.isArray(trafficData) ? trafficData : [])

      setProtocols(
        protocolData &&
          typeof protocolData === 'object' &&
          !Array.isArray(protocolData)
          ? protocolData
          : {}
      )

      setAttacks(Array.isArray(attackData) ? attackData : [])
    } catch (err) {
      setError(err.message || 'Unable to load analytics.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    loadAnalytics()

    const interval = setInterval(() => {
      loadAnalytics()
    }, 10000)

    return () => clearInterval(interval)
  }, [])

  const trafficByTime = Object.values(
    traffic.reduce((groups, record) => {
      const timestamp = String(record.timestamp || '')

      if (timestamp.length < 16) {
        return groups
      }

      const label = timestamp.slice(0, 16)

      if (!groups[label]) {
        groups[label] = {
          time: label,
          records: 0,
        }
      }

      groups[label].records += 1

      return groups
    }, {})
  )
    .sort((a, b) => a.time.localeCompare(b.time))
    .slice(-12)

  const protocolData = Object.entries(protocols).map(([name, value]) => ({
    name,
    value: Number(value) || 0,
  }))

  const scoreRanges = [
    { range: '0', min: 0, max: 0 },
    { range: '1–24', min: 1, max: 24 },
    { range: '25–49', min: 25, max: 49 },
    { range: '50–74', min: 50, max: 74 },
    { range: '75–100', min: 75, max: 100 },
  ]

  const threatScoreData = scoreRanges.map(({ range, min, max }) => ({
    range,
    records: traffic.filter((record) => {
      const score = Number(record.threat_score) || 0
      return score >= min && score <= max
    }).length,
  }))

  const averageThreatScore = traffic.length
    ? (
        traffic.reduce(
          (total, record) =>
            total + (Number(record.threat_score) || 0),
          0
        ) / traffic.length
      ).toFixed(1)
    : '0.0'

  return (
    <div className="analytics-page">
      <div className="analytics-toolbar">
        <div>
          <h2>Network Analytics</h2>
          <p>Insights calculated from recorded NIDS data</p>
        </div>

        <button
          type="button"
          className="traffic-refresh-button"
          onClick={() => loadAnalytics(true)}
          disabled={refreshing}
        >
          <RefreshCw
            size={15}
            className={refreshing ? 'refresh-icon-spinning' : ''}
          />
          Refresh
        </button>
      </div>

      {error && (
        <div className="dashboard-error">
          Unable to load analytics: {error}
        </div>
      )}

      <div className="analytics-summary-grid">
        <article className="analytics-summary-card">
          <Activity size={19} />
          <span>Traffic records loaded</span>
          <strong>{loading ? '—' : traffic.length}</strong>
        </article>

        <article className="analytics-summary-card">
          <ChartNoAxesCombined size={19} />
          <span>Protocols observed</span>
          <strong>{loading ? '—' : protocolData.length}</strong>
        </article>

        <article className="analytics-summary-card">
          <ShieldAlert size={19} />
          <span>Recorded attacks</span>
          <strong>{loading ? '—' : attacks.length}</strong>
        </article>

        <article className="analytics-summary-card">
          <Activity size={19} />
          <span>Average traffic threat score</span>
          <strong>{loading ? '—' : averageThreatScore}</strong>
        </article>
      </div>

      <div className="analytics-charts-grid">
        <section className="chart-card analytics-wide-chart">
          <div className="chart-card-header">
            <div>
              <h3>Traffic Trends</h3>
              <p>Records grouped by timestamp</p>
            </div>
          </div>

          {loading ? (
            <div className="chart-state">Loading traffic data...</div>
          ) : trafficByTime.length === 0 ? (
            <div className="chart-state">No traffic data available.</div>
          ) : (
            <div className="analytics-chart">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trafficByTime}>
                  <CartesianGrid
                    stroke="var(--border)"
                    strokeDasharray="3 3"
                  />
                  <XAxis
                    dataKey="time"
                    tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                  />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="records"
                    name="Traffic records"
                    stroke="#83c4d7"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="chart-card">
          <div className="chart-card-header">
            <div>
              <h3>Protocol Distribution</h3>
              <p>Recorded traffic by protocol</p>
            </div>
          </div>

          {loading ? (
            <div className="chart-state">Loading protocol data...</div>
          ) : protocolData.length === 0 ? (
            <div className="chart-state">No protocol data available.</div>
          ) : (
            <div className="analytics-chart">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocolData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={78}
                    innerRadius={48}
                    paddingAngle={3}
                  >
                    {protocolData.map((entry, index) => (
                      <Cell
                        key={entry.name}
                        fill={CHART_COLORS[index % CHART_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <section className="chart-card analytics-wide-chart">
          <div className="chart-card-header">
            <div>
              <h3>Threat Score Distribution</h3>
              <p>Traffic records grouped by stored threat score</p>
            </div>
          </div>

          {loading ? (
            <div className="chart-state">Loading threat score data...</div>
          ) : traffic.length === 0 ? (
            <div className="chart-state">No traffic data available.</div>
          ) : (
            <div className="analytics-chart">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatScoreData}>
                  <CartesianGrid
                    stroke="var(--border)"
                    strokeDasharray="3 3"
                  />
                  <XAxis
                    dataKey="range"
                    tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                  />
                  <Tooltip />
                  <Bar
                    dataKey="records"
                    name="Traffic records"
                    fill="#83c4d7"
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

export default Analytics