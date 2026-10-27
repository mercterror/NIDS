import { useCallback, useEffect, useState } from 'react'
import { RefreshCw, ShieldAlert, X } from 'lucide-react'

import { apiRequest } from '../services/api'

function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [selectedAlert, setSelectedAlert] = useState(null)

  const loadAlerts = useCallback(async () => {
    setRefreshing(true)

    try {
      const data = await apiRequest('/api/attacks')
      setAlerts(Array.isArray(data) ? data : [])
      setError('')
    } catch (err) {
      setError(err.message || 'Unable to load alerts.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    loadAlerts()

    const interval = setInterval(loadAlerts, 10000)

    return () => clearInterval(interval)
  }, [loadAlerts])

  const normalizedSeverity = alert =>
    String(alert.severity || '').trim().toUpperCase()

  const highSeverity = alerts.filter(
    alert => normalizedSeverity(alert) === 'HIGH'
  ).length

  const criticalSeverity = alerts.filter(
    alert => normalizedSeverity(alert) === 'CRITICAL'
  ).length

  const mediumSeverity = alerts.filter(
    alert => normalizedSeverity(alert) === 'MEDIUM'
  ).length

  const lowSeverity = alerts.filter(
    alert => normalizedSeverity(alert) === 'LOW'
  ).length

  const unknownSeverity = alerts.filter(
    alert =>
      !['HIGH', 'CRITICAL', 'MEDIUM', 'LOW'].includes(
        normalizedSeverity(alert)
      )
  ).length

  return (
    <div className="alerts-page">
      <div className="alerts-summary-grid">
        <article className="alerts-summary-card">
          <span>Total alerts</span>
          <strong>{alerts.length}</strong>
        </article>

        <article className="alerts-summary-card">
          <span>High</span>
          <strong>{highSeverity}</strong>
        </article>

        <article className="alerts-summary-card">
          <span>Critical</span>
          <strong>{criticalSeverity}</strong>
        </article>

        <article className="alerts-summary-card">
          <span>Medium</span>
          <strong>{mediumSeverity}</strong>
        </article>

        <article className="alerts-summary-card">
          <span>Low</span>
          <strong>{lowSeverity}</strong>
        </article>

        <article className="alerts-summary-card">
          <span>Other / Unknown</span>
          <strong>{unknownSeverity}</strong>
        </article>
      </div>

      <section className="alerts-table-card">
        <div className="alerts-toolbar">
          <div>
            <h2>Detected Incidents</h2>
            <p>Attack records reported by the NIDS backend</p>
          </div>

          <button
            type="button"
            className="traffic-refresh-button"
            onClick={loadAlerts}
            disabled={refreshing}
          >
            <RefreshCw
              size={15}
              className={refreshing ? 'refresh-icon-spinning' : ''}
            />
            Refresh
          </button>
        </div>

        {error ? (
          <div className="alerts-empty-state">
            <ShieldAlert size={28} />
            <h3>Unable to load alerts</h3>
            <p>{error}</p>
          </div>
        ) : loading ? (
          <div className="alerts-empty-state">
            <p>Loading attack records...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="alerts-empty-state">
            <ShieldAlert size={30} />
            <h3>No attack records yet</h3>
            <p>
              No attacks have been stored in the database.
              Detected incidents will appear here when recorded.
            </p>
          </div>
        ) : (
          <div className="alerts-table-wrapper">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Attack type</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Severity</th>
                  <th>Threat score</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert, index) => (
                  <tr
                    key={alert.id ?? index}
                    className="alert-row-clickable"
                    onClick={() => setSelectedAlert(alert)}
                    tabIndex={0}
                    onKeyDown={event => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        setSelectedAlert(alert)
                      }
                    }}
                  >
                    <td>{alert.timestamp || '—'}</td>
                    <td>{alert.attack_type || 'Unknown'}</td>
                    <td>{alert.src_ip || '—'}</td>
                    <td>{alert.dst_ip || '—'}</td>
                    <td>{alert.protocol || '—'}</td>
                    <td>
                      <span
                        className={`alert-severity alert-severity-${String(
                          alert.severity || 'unknown'
                        ).toLowerCase()}`}
                      >
                        {alert.severity || 'Unknown'}
                      </span>
                    </td>
                    <td>{alert.threat_score ?? '—'}</td>
                    <td>{alert.status || 'Detected'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
            </section>

      {selectedAlert && (
        <div
          className="incident-panel-backdrop"
          onClick={() => setSelectedAlert(null)}
        >
          <aside
            className="incident-details-panel"
            onClick={event => event.stopPropagation()}
          >
            <div className="incident-panel-header">
              <div>
                <h2>Incident Details</h2>
                <p>Detailed information about this alert</p>
              </div>

              <button
                type="button"
                className="incident-panel-close"
                onClick={() => setSelectedAlert(null)}
                aria-label="Close incident details"
              >
                <X size={18} />
              </button>
            </div>

            <div className="incident-panel-content">
              <div className="incident-detail-section">
                <h3>Incident Information</h3>

                <div className="incident-detail-item">
                  <span>Attack type</span>
                  <strong>{selectedAlert.attack_type || 'Unavailable'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Timestamp</span>
                  <strong>{selectedAlert.timestamp || 'Unavailable'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Source IP</span>
                  <strong>{selectedAlert.src_ip || 'Unavailable'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Destination IP</span>
                  <strong>{selectedAlert.dst_ip || 'Unavailable'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Protocol</span>
                  <strong>{selectedAlert.protocol || 'Unavailable'}</strong>
                </div>
              </div>

              <div className="incident-detail-section">
                <h3>Threat Assessment</h3>

                <div className="incident-detail-item">
                  <span>Severity</span>
                  <strong>{selectedAlert.severity || 'Unknown'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Threat score</span>
                  <strong>{selectedAlert.threat_score ?? 'Unavailable'}</strong>
                </div>

                <div className="incident-detail-item">
                  <span>Confidence</span>
                  <strong>
                    {selectedAlert.confidence ?? 'Unavailable'}
                  </strong>
                </div>
              </div>

              <div className="incident-detail-section">
                <h3>Response Status</h3>

                <div className="incident-detail-item">
                  <span>Status</span>
                  <strong>{selectedAlert.status || 'Detected'}</strong>
                </div>

                <p className="incident-detail-note">
                  This status reflects the stored incident record. It does
                  not independently confirm that a blocking action was enforced.
                </p>
              </div>

              <div className="incident-detail-section">
                <h3>Detection Evidence</h3>

                {selectedAlert.features ? (
                  <pre className="incident-evidence">
                    {typeof selectedAlert.features === 'string'
                      ? (() => {
                          try {
                            return JSON.stringify(
                              JSON.parse(selectedAlert.features),
                              null,
                              2
                            )
                          } catch {
                            return selectedAlert.features
                          }
                        })()
                      : JSON.stringify(selectedAlert.features, null, 2)}
                  </pre>
                ) : (
                  <p className="incident-detail-note">
                    No detection evidence is available in this record.
                  </p>
                )}
              </div>
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}

export default Alerts