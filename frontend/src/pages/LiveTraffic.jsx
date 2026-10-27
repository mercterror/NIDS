
import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, RefreshCw, ChevronLeft, ChevronRight, X } from 'lucide-react'

import { apiRequest } from '../services/api'
const PAGE_SIZE = 10

function formatTimestamp(timestamp) {
  if (!timestamp) return '—'

  const date = new Date(timestamp.replace(' ', 'T'))

  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleString()
}

function LiveTraffic() {
  const [records, setRecords] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [protocol, setProtocol] = useState('all')
  const [threatFilter, setThreatFilter] = useState('all')
  const [sortKey, setSortKey] = useState('timestamp')
  const [sortDirection, setSortDirection] = useState('desc')
  const [page, setPage] = useState(1)
  const [selectedRecord, setSelectedRecord] = useState(null)
  const requestInProgress = useRef(false)

async function loadTraffic(isManual = false) {
  if (requestInProgress.current) return

  requestInProgress.current = true

  if (isManual) {
    setRefreshing(true)
  }

  try {
    const data = await apiRequest('/api/traffic')

    setRecords(Array.isArray(data) ? data : [])
    setError('')
  } catch {
    setError('Could not load traffic records. Check that Flask is running.')
  } finally {
    setLoading(false)
    setRefreshing(false)
    requestInProgress.current = false
  }
}

  useEffect(() => {
    loadTraffic()

    const intervalId = setInterval(() => loadTraffic(), 10000)

    return () => clearInterval(intervalId)
  }, [])

  const protocols = useMemo(
    () => [...new Set(records.map((record) => record.protocol).filter(Boolean))].sort(),
    [records],
  )

  const filteredRecords = useMemo(() => {
    const query = search.trim().toLowerCase()

    const filtered = records.filter((record) => {
      const matchesSearch =
        !query ||
        [
          record.src_ip,
          record.dst_ip,
          record.protocol,
          record.src_port,
          record.dst_port,
        ].some((value) => String(value ?? '').toLowerCase().includes(query))

      const matchesProtocol =
        protocol === 'all' || record.protocol === protocol

      const score = Number(record.threat_score ?? 0)

      const matchesThreat =
        threatFilter === 'all' ||
        (threatFilter === 'positive' && score > 0) ||
        (threatFilter === 'zero' && score === 0)

      return matchesSearch && matchesProtocol && matchesThreat
    })

    return filtered.sort((a, b) => {
      const first = a[sortKey]
      const second = b[sortKey]

      let comparison

      if (sortKey === 'timestamp') {
        comparison = String(first ?? '').localeCompare(String(second ?? ''))
      } else if (typeof first === 'number' || typeof second === 'number') {
        comparison = Number(first ?? 0) - Number(second ?? 0)
      } else {
        comparison = String(first ?? '').localeCompare(String(second ?? ''))
      }

      return sortDirection === 'asc' ? comparison : -comparison
    })
  }, [records, search, protocol, threatFilter, sortKey, sortDirection])

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const startIndex = (currentPage - 1) * PAGE_SIZE
  const visibleRecords = filteredRecords.slice(startIndex, startIndex + PAGE_SIZE)

  function changeSort(key) {
    if (sortKey === key) {
      setSortDirection((previous) => previous === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDirection(key === 'timestamp' ? 'desc' : 'asc')
    }

    setPage(1)
  }

  function sortLabel(key, label) {
    if (sortKey !== key) return label
    return `${label} ${sortDirection === 'asc' ? '↑' : '↓'}`
  }

  return (
    <div className="live-traffic-page">
      <section className="traffic-summary-grid">
        <article className="traffic-summary-card">
          <span>Total records</span>
          <strong>{records.length}</strong>
        </article>

        <article className="traffic-summary-card">
          <span>Filtered records</span>
          <strong>{filteredRecords.length}</strong>
        </article>

        <article className="traffic-summary-card">
          <span>Protocols observed</span>
          <strong>{protocols.length}</strong>
        </article>

        <article className="traffic-summary-card">
          <span>Positive threat scores</span>
          <strong>
            {records.filter((record) => Number(record.threat_score) > 0).length}
          </strong>
        </article>
      </section>

      <section className="traffic-table-card">
        <div className="traffic-toolbar">
          <div className="traffic-search">
            <Search size={17} />
            <input
              value={search}
              onChange={(event) => {
                setSearch(event.target.value)
                setPage(1)
              }}
              placeholder="Search IP, protocol or port..."
              aria-label="Search traffic"
            />
            {search && (
              <button
                type="button"
                className="traffic-clear-search"
                onClick={() => {
                  setSearch('')
                  setPage(1)
                }}
                aria-label="Clear search"
              >
                <X size={15} />
              </button>
            )}
          </div>

          <select
            value={protocol}
            onChange={(event) => {
              setProtocol(event.target.value)
              setPage(1)
            }}
            aria-label="Filter by protocol"
          >
            <option value="all">All protocols</option>
            {protocols.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>

          <select
            value={threatFilter}
            onChange={(event) => {
              setThreatFilter(event.target.value)
              setPage(1)
            }}
            aria-label="Filter by threat score"
          >
            <option value="all">All threat scores</option>
            <option value="positive">Score above zero</option>
            <option value="zero">Score equals zero</option>
          </select>

          <button
            type="button"
            className="traffic-refresh-button"
            onClick={() => loadTraffic(true)}
            disabled={refreshing}
          >
            <RefreshCw
              size={15}
              className={refreshing ? 'refresh-icon-spinning' : ''}
            />
            Refresh
          </button>
        </div>

        {error && <div className="dashboard-error">{error}</div>}

        {loading ? (
          <div className="table-state">Loading traffic records...</div>
        ) : filteredRecords.length === 0 ? (
          <div className="table-state">No records match your filters.</div>
        ) : (
          <>
            <div className="recent-traffic-table-wrap">
              <table className="recent-traffic-table live-traffic-table">
                <thead>
                  <tr>
                    <th>
                      <button type="button" onClick={() => changeSort('timestamp')}>
                        {sortLabel('timestamp', 'Timestamp')}
                      </button>
                    </th>
                    <th>
                      <button type="button" onClick={() => changeSort('src_ip')}>
                        {sortLabel('src_ip', 'Source IP')}
                      </button>
                    </th>
                    <th>
                      <button type="button" onClick={() => changeSort('dst_ip')}>
                        {sortLabel('dst_ip', 'Destination IP')}
                      </button>
                    </th>
                    <th>Ports</th>
                    <th>
                      <button type="button" onClick={() => changeSort('protocol')}>
                        {sortLabel('protocol', 'Protocol')}
                      </button>
                    </th>
                    <th>
                      <button type="button" onClick={() => changeSort('threat_score')}>
                        {sortLabel('threat_score', 'Threat score')}
                      </button>
                    </th>
                    <th>Details</th>
                  </tr>
                </thead>

                <tbody>
                  {visibleRecords.map((record) => (
                    <tr key={record.id}>
                      <td className="traffic-time">
                        {formatTimestamp(record.timestamp)}
                      </td>
                      <td className="traffic-ip">{record.src_ip ?? '—'}</td>
                      <td className="traffic-ip">{record.dst_ip ?? '—'}</td>
                      <td>{record.src_port ?? '—'} → {record.dst_port ?? '—'}</td>
                      <td>
                        <span className="protocol-tag">
                          {record.protocol ?? 'Unknown'}
                        </span>
                      </td>
                      <td>{record.threat_score ?? '—'}</td>
                      <td>
                        <button
                          type="button"
                          className="traffic-details-button"
                          onClick={() => setSelectedRecord(record)}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="traffic-pagination">
              <span>
                Showing {startIndex + 1}–{Math.min(startIndex + PAGE_SIZE, filteredRecords.length)}
                {' '}of {filteredRecords.length}
              </span>

              <div className="traffic-pagination-controls">
                <button
                  type="button"
                  onClick={() => setPage((previous) => Math.max(1, previous - 1))}
                  disabled={currentPage === 1}
                  aria-label="Previous page"
                >
                  <ChevronLeft size={16} />
                </button>
                <span>Page {currentPage} of {totalPages}</span>
                <button
                  type="button"
                  onClick={() => setPage((previous) => Math.min(totalPages, previous + 1))}
                  disabled={currentPage === totalPages}
                  aria-label="Next page"
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </section>

      {selectedRecord && (
        <div
          className="traffic-detail-backdrop"
          onClick={() => setSelectedRecord(null)}
        >
          <aside
            className="traffic-detail-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="traffic-detail-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="traffic-detail-header">
              <div>
                <h2 id="traffic-detail-title">Traffic Record</h2>
                <p>Record ID: {selectedRecord.id}</p>
              </div>
              <button
                type="button"
                className="traffic-detail-close"
                onClick={() => setSelectedRecord(null)}
                aria-label="Close details"
              >
                <X size={18} />
              </button>
            </div>

            <dl className="traffic-detail-list">
              {[
                ['Timestamp', formatTimestamp(selectedRecord.timestamp)],
                ['Source IP', selectedRecord.src_ip],
                ['Source port', selectedRecord.src_port],
                ['Destination IP', selectedRecord.dst_ip],
                ['Destination port', selectedRecord.dst_port],
                ['Protocol', selectedRecord.protocol],
                ['Packet count', selectedRecord.packet_count],
                ['Byte count', selectedRecord.byte_count],
                ['Packet rate', selectedRecord.packet_rate],
                ['Byte rate', selectedRecord.byte_rate],
                ['Flow duration', selectedRecord.flow_duration],
                ['Entropy score', selectedRecord.entropy_score],
                ['Threat score', selectedRecord.threat_score],
              ].map(([label, value]) => (
                <div key={label} className="traffic-detail-row">
                  <dt>{label}</dt>
                  <dd>{value ?? '—'}</dd>
                </div>
              ))}
            </dl>
          </aside>
        </div>
      )}
    </div>
  )
}

export default LiveTraffic
