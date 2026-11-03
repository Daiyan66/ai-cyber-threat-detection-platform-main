import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell, CartesianGrid } from 'recharts';

const DistributionTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const dataPoint = payload[0].payload;
    return (
      <div className="bg-slate-900/90 border border-slate-800 p-3 rounded-lg shadow-xl backdrop-blur-md">
        <p className="text-sm font-semibold text-slate-100">{dataPoint.attack_type}</p>
        <p className="text-xs text-slate-400 mt-1">
          Count: <span className="text-slate-200 font-bold">{dataPoint.count.toLocaleString()}</span>
        </p>
      </div>
    );
  }
  return null;
};

const DistributionChart = ({ data }) => {
  const getBarColor = (name) => {
    switch (name) {
      case 'Benign':
      case 'Normal': return '#10b981'; // Green
      case 'DDoS': return '#f43f5e'; // Rose/Red
      case 'Brute Force': return '#f97316'; // Orange
      case 'Web Attack': return '#a855f7'; // Purple
      case 'Botnet': return '#06b6d4'; // Cyan
      case 'PortScan':
      case 'Port Scan': return '#fbbf24'; // Amber
      default: return '#38bdf8'; // Sky Blue
    }
  };

  return (
    <div className="w-full h-[280px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis 
            dataKey="attack_type" 
            stroke="#64748b" 
            fontSize={12}
            tickLine={false}
            axisLine={false}
          />
          <YAxis 
            stroke="#64748b" 
            fontSize={11}
            tickLine={false}
            axisLine={false}
            tickFormatter={(value) => value >= 1000 ? `${(value/1000).toFixed(0)}k` : value}
          />
          <Tooltip content={<DistributionTooltip />} cursor={{ fill: '#334155', opacity: 0.1 }} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={getBarColor(entry.attack_type)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default DistributionChart;
