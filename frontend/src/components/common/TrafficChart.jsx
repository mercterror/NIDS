
import { useEffect, useState } from 'react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { apiRequest } from '../../services/api'

function TrafficChart() {
  const [trafficData, setTrafficData] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let isMounted = true

    async function loadTraffic() {
      try {
        const records = await apiRequest('/api/traffic')

        const groupedRecords = new Map()

        records.forEach((record) => {
          if (!record.timestamp) return

          const date = new Date(record.timestamp.replace(' ', 'T'))

          if (Number.isNaN(date.getTime())) return

          const minuteKey = `${record.timestamp.slice(0, 16)}`

          groupedRecords.set(
            minuteKey,
            (groupedRecords.get(minuteKey) ?? 0) + 1,
          )
        })

        const chartData = Array.from(groupedRecords, ([minuteKey, count]) => {
          const date = new Date(minuteKey.replace(' ', 'T'))

          return {
            timestamp: minuteKey,
            time: date.toLocaleString([], {
              month: 'short',
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
            }),
            count,
          }
        }).sort((a, b) => a.timestamp.localeCompare(b.timestamp))

        if (isMounted) {
          setTrafficData(chartData)
          setError('')
        }
      } catch {
        if (isMounted) {
          setError('Could not load traffic records.')
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
    <section className="chart-card">
      <div className="chart-card-header">
        <div>
          <h2>Traffic Over Time</h2>
          <p>Observed traffic records grouped by time</p>
        </div>
      </div>

      {loading ? (
        <div className="chart-state">Loading traffic data...</div>
      ) : error ? (
        <div className="chart-state chart-state-error">{error}</div>
      ) : trafficData.length === 0 ? (
        <div className="chart-state">No timestamped traffic data available.</div>
      ) : (
        <div className="traffic-chart">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={trafficData}
              margin={{ top: 10, right: 12, left: -12, bottom: 4 }}
            >
              <CartesianGrid
                stroke="#354653"
                strokeDasharray="3 3"
                vertical={false}
              />

              <XAxis
                dataKey="time"
                tick={{ fill: '#a5b5c3', fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: '#354653' }}
                minTickGap={24}
              />

              <YAxis
                allowDecimals={false}
                tick={{ fill: '#a5b5c3', fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />

              <Tooltip
                formatter={(value) => [value, 'Traffic records']}
                contentStyle={{
                  background: '#202f3d',
                  border: '1px solid #354653',
                  borderRadius: '8px',
                  color: '#e3edf4',
                }}
              />

              <Line
                type="monotone"
                dataKey="count"
                name="Traffic records"
                stroke="#83c4d7"
                strokeWidth={2.5}
                dot={false}
                activeDot={{ r: 5, fill: '#83c4d7' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  )
}

export default TrafficChart
