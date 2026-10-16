
import { Activity } from 'lucide-react'

function MetricCard({
  title,
  value,
  description,
  icon: Icon = Activity,
  accent = 'cyan',
  loading = false,
}) {
  return (
    <article className={`metric-card metric-card-${accent}`}>
      <div className="metric-card-top">
        <span className="metric-card-title">{title}</span>

        <div className="metric-card-icon">
          <Icon size={19} strokeWidth={1.8} />
        </div>
      </div>

      <div className="metric-card-value">
        {loading ? (
          <span className="metric-loading">Loading...</span>
        ) : (
          value ?? '—'
        )}
      </div>

      {description && (
        <p className="metric-card-description">{description}</p>
      )}
    </article>
  )
}

export default MetricCard
