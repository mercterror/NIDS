import { useEffect, useState } from 'react'
import { Monitor, RefreshCw, Search } from 'lucide-react'

import { apiRequest } from '../services/api'

function Devices() {
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  async function loadDevices() {
    try {
      const data = await apiRequest('/api/devices')

      setDevices(Array.isArray(data) ? data : [])
    } catch (err) {
      setError(err.message || 'Unable to load devices.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDevices()

    const interval = setInterval(loadDevices, 10000)

    return () => clearInterval(interval)
  }, [])

  const filteredDevices = devices.filter(device => {
    const searchText = search.toLowerCase()

    return [
      device.ip_address,
      device.mac_address,
      device.hostname,
      device.vendor,
      device.risk_level,
    ].some(value =>
      String(value || '').toLowerCase().includes(searchText)
    )
  })

  const highRiskDevices = devices.filter(device =>
    ['HIGH', 'CRITICAL'].includes(
      String(device.risk_level || '').toUpperCase()
    )
  ).length

  return (
    <div className="devices-page">
      <div className="devices-summary-grid">
        <article className="devices-summary-card">
          <span>Registered devices</span>
          <strong>{devices.length}</strong>
        </article>

        <article className="devices-summary-card">
          <span>High-risk devices</span>
          <strong>{highRiskDevices}</strong>
        </article>

        <article className="devices-summary-card">
          <span>Devices displayed</span>
          <strong>{filteredDevices.length}</strong>
        </article>
      </div>

      <section className="devices-table-card">
        <div className="devices-toolbar">
          <div>
            <h2>Device Inventory</h2>
            <p>Devices recorded by the NIDS backend</p>
          </div>

          <button
            type="button"
            className="traffic-refresh-button"
            onClick={loadDevices}
            disabled={loading}
          >
            <RefreshCw size={15} />
            Refresh
          </button>
        </div>

        <div className="devices-search-row">
          <Search size={17} />

          <input
            type="text"
            placeholder="Search IP, MAC, hostname or vendor..."
            value={search}
            onChange={event => setSearch(event.target.value)}
            aria-label="Search devices"
          />
        </div>

        {error ? (
          <div className="devices-empty-state">
            <Monitor size={30} />
            <h3>Unable to load devices</h3>
            <p>{error}</p>
          </div>
        ) : loading ? (
          <div className="devices-empty-state">
            <p>Loading device records...</p>
          </div>
        ) : filteredDevices.length === 0 ? (
          <div className="devices-empty-state">
            <Monitor size={30} />
            <h3>
              {search ? 'No matching devices' : 'No devices recorded yet'}
            </h3>
            <p>
              {search
                ? 'Try a different search term.'
                : 'Devices will appear here when they are recorded by the NIDS backend.'}
            </p>
          </div>
        ) : (
          <div className="devices-table-wrapper">
            <table className="devices-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Hostname</th>
                  <th>Vendor</th>
                  <th>Risk Level</th>
                  <th>Last Seen</th>
                </tr>
              </thead>

              <tbody>
                {filteredDevices.map((device, index) => (
                  <tr key={device.id ?? device.ip_address ?? index}>
                    <td>{device.ip_address || '—'}</td>
                    <td>{device.mac_address || '—'}</td>
                    <td>{device.hostname || 'Unknown'}</td>
                    <td>{device.vendor || 'Unknown'}</td>
                    <td>
                      <span
                        className={`device-risk device-risk-${String(
                          device.risk_level || 'unknown'
                        ).toLowerCase()}`}
                      >
                        {device.risk_level || 'Unknown'}
                      </span>
                    </td>
                    <td>{device.last_seen || '—'}</td>
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

export default Devices