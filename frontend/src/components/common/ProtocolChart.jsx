
import { useEffect, useState } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { apiRequest } from '../../services/api'

const COLORS = ['#83c4d7', '#9bb9e5', '#8fc9a8', '#e2b86b']

function ProtocolChart() {
  const [protocols, setProtocols] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let isMounted = true

    async function loadProtocols() {
      try {
        const data = await apiRequest('/api/protocols')

        const chartData = Object.entries(data)
          .map(([name, value]) => ({
            name,
            value: Number(value),
          }))
          .filter((item) => Number.isFinite(item.value) && item.value > 0)

        if (isMounted) {
          setProtocols(chartData)
          setError('')
        }
      } catch {
        if (isMounted) {
          setError('Could not load protocol distribution.')
        }
      } finally {
        if (isMounted) {
          setLoading(false)
        }
      }
    }

    loadProtocols()

    const intervalId = setInterval(loadProtocols, 10000)

    return () => {
      isMounted = false
      clearInterval(intervalId)
    }
  }, [])

  const total = protocols.reduce((sum, item) => sum + item.value, 0)

  return (
    <section className="chart-card">
      <div className="chart-card-header">
        <div>
          <h2>Protocol Distribution</h2>
          <p>Observed traffic by protocol</p>
        </div>
        <span className="chart-total">{total.toLocaleString()} records</span>
      </div>

      {loading ? (
        <div className="chart-state">Loading protocol data...</div>
      ) : error ? (
        <div className="chart-state chart-state-error">{error}</div>
      ) : protocols.length === 0 ? (
        <div className="chart-state">No protocol data available.</div>
      ) : (
        <div className="protocol-chart-layout">
          <div className="protocol-chart">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocols}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius="62%"
                  outerRadius="84%"
                  paddingAngle={3}
                  stroke="none"
                >
                  {protocols.map((item, index) => (
                    <Cell
                      key={item.name}
                      fill={COLORS[index % COLORS.length]}
                    />
                  ))}
                </Pie>

                <Tooltip
                  formatter={(value, name) => [
                    Number(value).toLocaleString(),
                    name,
                  ]}
                  contentStyle={{
                    background: '#202f3d',
                    border: '1px solid #354653',
                    borderRadius: '8px',
                    color: '#e3edf4',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>

            <div className="protocol-chart-center">
              <strong>{total.toLocaleString()}</strong>
              <span>Records</span>
            </div>
          </div>

          <div className="protocol-legend">
            {protocols.map((item, index) => (
              <div className="protocol-legend-item" key={item.name}>
                <span
                  className="protocol-legend-dot"
                  style={{ backgroundColor: COLORS[index % COLORS.length] }}
                />
                <span className="protocol-legend-name">{item.name}</span>
                <strong>{item.value.toLocaleString()}</strong>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}

export default ProtocolChart
