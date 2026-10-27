import { useEffect, useState } from 'react'
import { Ban, RefreshCw, Search } from 'lucide-react'
import { apiRequest } from '../services/api'

function BlockedEntities() {
  const [entities, setEntities] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  async function loadEntities(isManual = false) {
    if (isManual) {
      setRefreshing(true)
    }

    try {
      setError('')

      const data = await apiRequest('/api/blocked')
      setEntities(Array.isArray(data) ? data : [])
    } catch (err) {
      setError(err.message || 'Unable to load blocked entities.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    loadEntities()

    const interval = setInterval(() => {
      loadEntities()
    }, 10000)

    return () => clearInterval(interval)
  }, [])

  const filteredEntities = entities.filter((entity) =>
    [
      entity.ip_address,
      entity.reason,
      entity.blocked_at,
      entity.expires_at,
    ].some((value) =>
      String(value || '').toLowerCase().includes(search.toLowerCase())
    )
  )

  return (
    <div className="blocked-page">
      <div className="blocked-summary-grid">
        <article className="blocked-summary-card">
          <span>Recorded blocked IPs</span>
          <strong>{entities.length}</strong>
        </article>

        <article className="blocked-summary-card">
          <span>Matching records</span>
          <strong>{filteredEntities.length}</strong>
        </article>
      </div>

      <section className="blocked-table-card">
        <div className="blocked-toolbar">
          <div>
            <h2>Blocked IP Records</h2>
            <p>IP addresses recorded by the NIDS response system</p>
          </div>

          <button
            type="button"
            className="traffic-refresh-button"
            onClick={() => loadEntities(true)}
            disabled={refreshing}
          >
            <RefreshCw
              size={15}
              className={refreshing ? 'refresh-icon-spinning' : ''}
            />
            Refresh
          </button>
        </div>

        <div className="blocked-search-row">
          <Search size={17} />

          <input
            type="text"
            placeholder="Search IP address or reason..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search blocked IP records"
          />
        </div>

        {error ? (
          <div className="blocked-empty-state">
            <Ban size={30} />
            <h3>Unable to load blocked records</h3>
            <p>{error}</p>
          </div>
        ) : loading ? (
          <div className="blocked-empty-state">
            <p>Loading blocked IP records...</p>
          </div>
        ) : filteredEntities.length === 0 ? (
          <div className="blocked-empty-state">
            <Ban size={30} />
            <h3>
              {search
                ? 'No matching records'
                : 'No blocked IPs recorded yet'}
            </h3>
            <p>
              {search
                ? 'Try a different search term.'
                : 'Recorded blocked IPs will appear here when the backend stores them.'}
            </p>
          </div>
        ) : (
          <div className="blocked-table-wrapper">
            <table className="blocked-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason</th>
                  <th>Recorded At</th>
                  <th>Expires At</th>
                  <th>Enforcement Status</th>
                </tr>
              </thead>

              <tbody>
                {filteredEntities.map((entity, index) => (
                  <tr key={entity.id ?? entity.ip_address ?? index}>
                    <td>{entity.ip_address || '—'}</td>
                    <td>{entity.reason || 'Not specified'}</td>
                    <td>{entity.blocked_at || '—'}</td>
                    <td>{entity.expires_at || 'No expiry recorded'}</td>
                    <td>
                      <span className="blocked-status">
                        Enforcement unverified
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

export default BlockedEntities