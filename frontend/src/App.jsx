import { useState, useEffect } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  LineChart, Line, PieChart, Pie, Cell, Legend
} from 'recharts'

const COLORS = {
  BENIGN: '#10b981', // green
  BOT: '#f59e0b', // yellow
  BRUTE_FORCE: '#f97316', // orange
  DDOS: '#ef4444', // red
  DOS: '#dc2626', // dark red
  PORT_SCAN: '#8b5cf6', // purple
  WEB_ATTACK: '#eab308', // dark yellow
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
}

function App() {
  const [stats, setStats] = useState(null)
  const [distribution, setDistribution] = useState([])
  const [timeline, setTimeline] = useState([])
  const [alerts, setAlerts] = useState([])
  const [error, setError] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)

  const fetchData = async () => {
    try {
      const [statsRes, distRes, timeRes, alertRes] = await Promise.all([
        fetch('http://127.0.0.1:8000/api/dashboard/stats'),
        fetch('http://127.0.0.1:8000/api/dashboard/attack-distribution'),
        fetch('http://127.0.0.1:8000/api/dashboard/timeline'),
        fetch('http://127.0.0.1:8000/api/dashboard/recent-alerts')
      ]);

      if (!statsRes.ok) throw new Error("Failed to fetch data")

      const statsData = await statsRes.json()
      const distData = await distRes.json()
      const timeData = await timeRes.json()
      const alertData = await alertRes.json()

      setStats(statsData)
      setDistribution(distData.distribution)
      setTimeline(timeData.timeline)
      setAlerts(alertData.alerts)
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  if (error) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 p-8 flex items-center justify-center font-sans">
        <div className="text-red-400 font-mono bg-red-950/30 p-6 rounded-lg border border-red-900/50 shadow-lg">
          Error connecting to backend: {error}
        </div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 p-8 flex items-center justify-center font-sans">
        <div className="text-slate-400 font-medium animate-pulse text-lg tracking-wide">
          Initializing Threat Intelligence Dashboard...
        </div>
      </div>
    )
  }

  const riskData = [
    { name: 'Critical', value: stats.critical, color: COLORS.CRITICAL },
    { name: 'High', value: stats.high, color: COLORS.HIGH },
    { name: 'Medium', value: stats.medium, color: COLORS.MEDIUM },
    { name: 'Low', value: stats.low, color: COLORS.LOW },
  ].filter(d => d.value > 0)

  // System font stack
  const appStyle = {
    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-6 md:p-8" style={appStyle}>
      <div className="max-w-screen-2xl mx-auto space-y-8">
        
        {/* HEADER */}
        <header className="border-b border-slate-800 pb-6 flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
          <div>
            <h1 className="text-3xl font-bold text-slate-100 tracking-tight">
              AI-Powered Network Threat Detection & Analytics
            </h1>
            <p className="text-slate-500 mt-1.5 font-medium">
              Real-time network security monitoring and threat intelligence
            </p>
          </div>
          <div className="flex items-center gap-2.5 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-md shadow-sm">
            <div className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </div>
            <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase">System Active</span>
          </div>
        </header>

        {/* STATISTICS */}
        <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
          {[
            { label: 'Total Events', value: stats.total_events, color: 'text-blue-400' },
            { label: 'Total Threats', value: stats.total_threats, color: 'text-rose-400' },
            { label: 'Critical', value: stats.critical, color: 'text-red-500' },
            { label: 'High', value: stats.high, color: 'text-orange-500' },
            { label: 'Medium', value: stats.medium, color: 'text-amber-500' },
            { label: 'Low', value: stats.low, color: 'text-emerald-500' }
          ].map((stat, idx) => (
            <div key={idx} className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-center">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">{stat.label}</span>
              <span className={`text-3xl font-bold tracking-tight ${stat.color}`}>
                {stat.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>

        {/* CHARTS ROW */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* Attack Distribution */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-6">Attack Distribution</h2>
            <div className="h-[280px]">
              {distribution.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={distribution} layout="vertical" margin={{ top: 0, right: 20, left: 20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                    <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                    <YAxis dataKey="attack_type" type="category" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} width={100} />
                    <RechartsTooltip 
                      cursor={{ fill: '#0f172a' }} 
                      contentStyle={{ backgroundColor: '#020617', borderColor: '#1e293b', borderRadius: '6px', color: '#f8fafc', fontSize: '12px' }} 
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={40}>
                      {distribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[entry.attack_type?.toUpperCase()] || '#475569'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-slate-600 text-sm">No data available</div>
              )}
            </div>
          </div>

          {/* Risk Distribution */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-6">Risk Distribution</h2>
            <div className="h-[280px]">
              {riskData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie 
                      data={riskData} 
                      dataKey="value" 
                      nameKey="name" 
                      cx="50%" cy="50%" 
                      innerRadius={70} 
                      outerRadius={100} 
                      stroke="none"
                      paddingAngle={2}
                    >
                      {riskData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: '#020617', borderColor: '#1e293b', borderRadius: '6px', color: '#f8fafc', fontSize: '12px' }} 
                    />
                    <Legend 
                      iconType="circle" 
                      wrapperStyle={{ fontSize: '12px', color: '#94a3b8' }} 
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-slate-600 text-sm">No data available</div>
              )}
            </div>
          </div>
        </div>

        {/* TIMELINE */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-6">Attack Timeline</h2>
          <div className="h-[240px]">
            {timeline.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timeline} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} dy={10} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} dx={-10} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#020617', borderColor: '#1e293b', borderRadius: '6px', color: '#f8fafc', fontSize: '12px' }} 
                  />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }} />
                  <Line type="monotone" dataKey="events" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3, fill: '#3b82f6', strokeWidth: 0 }} activeDot={{ r: 5 }} name="All Events" />
                  <Line type="monotone" dataKey="threats" stroke="#ef4444" strokeWidth={2} dot={{ r: 3, fill: '#ef4444', strokeWidth: 0 }} activeDot={{ r: 5 }} name="Threats" />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-slate-600 text-sm">No data available</div>
            )}
          </div>
        </div>

        {/* ALERTS */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="p-6 border-b border-slate-800">
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Recent Security Alerts</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-950/50">
                <tr>
                  <th className="py-4 px-6 font-semibold text-slate-400 text-xs uppercase tracking-wider">Time</th>
                  <th className="py-4 px-6 font-semibold text-slate-400 text-xs uppercase tracking-wider">Attack Type</th>
                  <th className="py-4 px-6 font-semibold text-slate-400 text-xs uppercase tracking-wider">Risk Level</th>
                  <th className="py-4 px-6 font-semibold text-slate-400 text-xs uppercase tracking-wider text-right">Confidence</th>
                  <th className="py-4 px-6 font-semibold text-slate-400 text-xs uppercase tracking-wider text-right">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {alerts.map((alert, i) => (
                  <tr 
                    key={i} 
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="py-4 px-6 text-slate-400 font-mono text-xs">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-2">
                        <span 
                          className="w-2 h-2 rounded-full" 
                          style={{ backgroundColor: COLORS[alert.attack_type?.toUpperCase()] || '#9ca3af' }}
                        ></span>
                        <span className="font-medium text-slate-200">{alert.attack_type}</span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold border ${
                        alert.risk_level === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        alert.risk_level === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                        alert.risk_level === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                        'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                      }`}>
                        {alert.risk_level}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right text-slate-300 font-mono text-xs">
                      {(alert.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="py-4 px-6 text-right">
                      <span className="font-mono text-xs text-slate-300 bg-slate-800/50 px-2.5 py-1 rounded border border-slate-700/50">
                        {alert.risk_score}
                      </span>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan="5" className="py-12 text-center text-slate-500 text-sm">
                      No recent security alerts
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* ALERT MODAL */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6" style={appStyle}>
          <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm transition-opacity" onClick={() => setSelectedAlert(null)}></div>
          
          <div className="relative bg-slate-900 border border-slate-700 rounded-xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-full">
            {/* Modal Header */}
            <div className="px-6 py-5 border-b border-slate-800 flex justify-between items-center bg-slate-800/20">
              <div className="flex items-center gap-3">
                <span 
                  className="w-3 h-3 rounded-full shadow-[0_0_8px_rgba(0,0,0,0.5)]"
                  style={{ backgroundColor: COLORS[selectedAlert.attack_type?.toUpperCase()] || '#fff' }}
                ></span>
                <h3 className="text-xl font-bold text-white tracking-tight uppercase">
                  {selectedAlert.attack_type} DETECTED
                </h3>
              </div>
              <button 
                onClick={() => setSelectedAlert(null)} 
                className="text-slate-500 hover:text-slate-300 transition-colors p-1"
                aria-label="Close"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
              </button>
            </div>
            
            {/* Modal Body */}
            <div className="p-6 overflow-y-auto">
              
              {/* Metrics Row */}
              <div className="grid grid-cols-3 gap-4 mb-8">
                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-4">
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">Risk Level</div>
                  <div className={`font-bold text-lg ${
                    selectedAlert.risk_level === 'CRITICAL' ? 'text-red-400' :
                    selectedAlert.risk_level === 'HIGH' ? 'text-orange-400' :
                    selectedAlert.risk_level === 'MEDIUM' ? 'text-amber-400' :
                    'text-emerald-400'
                  }`}>
                    {selectedAlert.risk_level}
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-4">
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">Risk Score</div>
                  <div className="font-mono font-medium text-lg text-slate-200">
                    {selectedAlert.risk_score} <span className="text-slate-500 text-sm">/100</span>
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-4">
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">Confidence</div>
                  <div className="font-mono font-medium text-lg text-slate-200">
                    {(selectedAlert.confidence * 100).toFixed(1)}%
                  </div>
                </div>
              </div>

              {/* Explanations */}
              <div className="space-y-6">
                <div>
                  <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Why was it flagged?</h4>
                  <div className="text-slate-300 leading-relaxed text-sm bg-slate-800/30 p-4 rounded-lg border border-slate-700/50">
                    {selectedAlert.explanation}
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Recommended Action</h4>
                  <div className="text-sky-300 leading-relaxed text-sm bg-sky-900/10 p-4 rounded-lg border border-sky-900/30">
                    {selectedAlert.recommended_action}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-slate-800 bg-slate-900 flex justify-end">
              <button 
                onClick={() => setSelectedAlert(null)}
                className="px-5 py-2 text-sm font-medium bg-slate-800 hover:bg-slate-700 text-white rounded-md transition-colors border border-slate-700"
              >
                Acknowledge & Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
