
import { useEffect, useState } from 'react'
import { apiRequest } from '../../services/api'

function formatTimestamp(timestamp) {
  if (!timestamp) return '—'

  const date = new Date(timestamp.replace(' ', 'T'))

  if (Number.isNaN(date.getTime())) return timestamp

  return date.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function RecentTraffic() {
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let isMounted = true

    async function loadTraffic() {
      try {
        const data = await apiRequest('/api/traffic')

        if (isMounted) {
          setRecords(Array.isArray(data) ? data.slice(0, 5) : [])
          setError('')
        }
      } catch {
        if (isMounted) {
          setError('Could not load recent traffic.')
        }
      } finally {
        if (isMounted) {
          setLoading(false)
        }
      }
    }

    loadTraffic()

    const intervalId = setInterval(loadTraffic, 10000)

    return () => {
      isMounted = false
      clearInterval(intervalId)
    }
  }, [])

  return (
    <section className="recent-traffic-card">
      <div className="recent-traffic-header">
        <div>
          <h2>Recent Traffic</h2>
          <p>Latest records reported by the backend</p>
        </div>
        <span className="recent-traffic-count">
          {records.length} records
        </span>
      </div>

      {loading ? (
        <div className="table-state">Loading traffic records...</div>
      ) : error ? (
        <div className="table-state table-state-error">{error}</div>
      ) : records.length === 0 ? (
        <div className="table-state">No traffic records available.</div>
      ) : (
        <div className="recent-traffic-table-wrap">
          <table className="recent-traffic-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Threat Score</th>
              </tr>
            </thead>

            <tbody>
              {records.map((record) => (
                <tr key={record.id}>
                  <td className="traffic-time">
                    {formatTimestamp(record.timestamp)}
                  </td>
                  <td className="traffic-ip">{record.src_ip ?? '—'}</td>
                  <td className="traffic-ip">{record.dst_ip ?? '—'}</td>
                  <td>
                    <span className="protocol-tag">
                      {record.protocol ?? 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className="threat-value">
                      {record.threat_score ?? '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default RecentTraffic
