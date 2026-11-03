import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from 'recharts';
import { Calendar, TrendingUp, AlertTriangle } from 'lucide-react';

import Loader from '../components/Loader';
import EmptyState from '../components/EmptyState';
import { getApiUrl } from '../utils/api';

const AnalyticsTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-xl shadow-2xl backdrop-blur-md">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <Calendar className="w-3.5 h-3.5 text-sky-400" />
          <span>{label}</span>
        </p>
        <div className="space-y-1.5 text-sm font-semibold">
          <p className="text-cyber-red flex items-center justify-between gap-6">
            <span>Critical:</span>
            <span>{payload[0].value.toLocaleString()}</span>
          </p>
          <p className="text-cyber-orange flex items-center justify-between gap-6">
            <span>High:</span>
            <span>{payload[1].value.toLocaleString()}</span>
          </p>
          <p className="text-cyber-yellow flex items-center justify-between gap-6">
            <span>Medium:</span>
            <span>{payload[2].value.toLocaleString()}</span>
          </p>
          <p className="text-cyber-green flex items-center justify-between gap-6">
            <span>Low / Benign:</span>
            <span>{payload[3].value.toLocaleString()}</span>
          </p>
          <div className="border-t border-slate-800/80 pt-1.5 mt-1.5 text-slate-200 flex items-center justify-between">
            <span>Total Volume:</span>
            <span className="font-bold">
              {(payload[0].value + payload[1].value + payload[2].value + payload[3].value).toLocaleString()}
            </span>
          </div>
        </div>
      </div>
    );
  }
  return null;
};

const Analytics = () => {
  const [loading, setLoading] = useState(true);
  const [trendData, setTrendData] = useState([]);
  const [days, setDays] = useState(30); // Default to 30 days window

  const fetchTrendData = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${getApiUrl()}/threats/trend`, {
        params: { days }
      });
      
      // Formatting time format for display
      const formatted = res.data.map(item => {
        const date = new Date(item.time);
        
        // If data is hourly (contains 'T'), format to show hour. If daily, show date.
        const displayTime = item.time.includes('T') 
          ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : date.toLocaleDateString([], { month: 'short', day: 'numeric' });
          
        return {
          ...item,
          displayTime
        };
      });
      
      setTrendData(formatted);
    } catch (err) {
      console.error("Failed to load trend analytics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrendData();
  }, [days]);

  return (
    <div className="space-y-6">
      
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-emerald-400" />
            <span>Threat Analytics</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">Monitor historical intrusion trends and severity classifications over time.</p>
        </div>
        
        {/* Days Window Selector */}
        <div className="bg-slate-900 border border-slate-800 p-1 rounded-lg flex items-center">
          {[7, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-all ${
                days === d 
                  ? 'bg-slate-800 text-slate-100 border border-slate-700/60 shadow' 
                  : 'text-slate-400 hover:text-slate-200 border border-transparent'
              }`}
            >
              {d} Days
            </button>
          ))}
        </div>
      </div>

      {/* Main Chart Panel */}
      <div className="glass-panel p-5 bg-slate-900/40">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">Intrusion volume timeline</h2>
          <span className="text-[10px] text-slate-500 font-bold uppercase">Time-bucketed aggregation</span>
        </div>

        {loading ? (
          <Loader message="Aggregating network data timestamps..." />
        ) : trendData.length === 0 ? (
          <EmptyState message="No traffic trend records found for this period." />
        ) : (
          <div className="w-full h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={trendData}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorMed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#fbbf24" stopOpacity={0.15}/>
                    <stop offset="95%" stopColor="#fbbf24" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.1}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis 
                  dataKey="displayTime" 
                  stroke="#64748b" 
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis 
                  stroke="#64748b" 
                  fontSize={11}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip content={<AnalyticsTooltip />} />
                <Legend 
                  verticalAlign="top" 
                  height={36} 
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => {
                    const mappings = {
                      critical: 'Critical',
                      high: 'High',
                      medium: 'Medium',
                      low: 'Low / Benign'
                    };
                    return <span className="text-xs font-semibold text-slate-300">{mappings[value] || value}</span>;
                  }}
                />
                {/* Area plots, stacked */}
                <Area 
                  type="monotone" 
                  dataKey="critical" 
                  stackId="1" 
                  stroke="#f43f5e" 
                  fillOpacity={1} 
                  fill="url(#colorCrit)" 
                  strokeWidth={2}
                />
                <Area 
                  type="monotone" 
                  dataKey="high" 
                  stackId="1" 
                  stroke="#f97316" 
                  fillOpacity={1} 
                  fill="url(#colorHigh)" 
                  strokeWidth={2}
                />
                <Area 
                  type="monotone" 
                  dataKey="medium" 
                  stackId="1" 
                  stroke="#fbbf24" 
                  fillOpacity={1} 
                  fill="url(#colorMed)" 
                  strokeWidth={2}
                />
                <Area 
                  type="monotone" 
                  dataKey="low" 
                  stackId="1" 
                  stroke="#10b981" 
                  fillOpacity={1} 
                  fill="url(#colorLow)" 
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Info Card */}
      <div className="glass-panel p-4 bg-slate-900/20 border-slate-800 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-cyber-yellow shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-semibold text-slate-200">Simulated Playback Sync</h4>
          <p className="text-xs text-slate-400 mt-1 leading-relaxed">
            Note: The data timeline is replayed from public labeled captures. For the current demo dataset, the trend aggregated hourly spans the CIC-IDS2017 flow telemetry logs loaded during database initialization.
          </p>
        </div>
      </div>

    </div>
  );
};

export default Analytics;
