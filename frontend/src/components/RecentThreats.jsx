import React from 'react';
import { ArrowUpRight } from 'lucide-react';

const RecentThreats = ({ threats, onSelectThreat }) => {
  const getSeverityBadge = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/10 text-cyber-red border-rose-500/20';
      case 'high':
        return 'bg-orange-500/10 text-cyber-orange border-orange-500/20';
      case 'medium':
        return 'bg-amber-500/10 text-cyber-yellow border-amber-500/20';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const formatTimestamp = (isoString) => {
    const date = new Date(isoString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left border-collapse">
        <thead>
          <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <th className="py-3 px-4">Time</th>
            <th className="py-3 px-4">Source IP</th>
            <th className="py-3 px-4">Destination IP</th>
            <th className="py-3 px-4">Attack Type</th>
            <th className="py-3 px-4">Severity</th>
            <th className="py-3 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/50 text-sm font-medium text-slate-200">
          {threats.map((threat) => (
            <tr 
              key={threat.id} 
              className="hover:bg-slate-900/40 transition-colors duration-150 cursor-pointer group"
              onClick={() => onSelectThreat(threat)}
            >
              <td className="py-3.5 px-4 text-slate-400">{formatTimestamp(threat.timestamp)}</td>
              <td className="py-3.5 px-4 font-mono">{threat.source_ip}</td>
              <td className="py-3.5 px-4 font-mono">{threat.destination_ip}</td>
              <td className="py-3.5 px-4">
                <div className="flex items-center gap-1.5">
                  <span className={threat.attack_type === 'Benign' || threat.attack_type === 'Normal' ? 'text-slate-400' : 'text-slate-100 font-semibold'}>
                    {threat.attack_type}
                  </span>
                  {threat.is_blocked && (
                    <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-950/40 text-emerald-400 border border-emerald-500/20">
                      BLOCKED
                    </span>
                  )}
                </div>
              </td>
              <td className="py-3.5 px-4">
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getSeverityBadge(threat.severity)}`}>
                  {threat.severity}
                </span>
              </td>
              <td className="py-3.5 px-4 text-right">
                <button className="text-slate-400 group-hover:text-emerald-400 transition-colors flex items-center justify-end ml-auto gap-0.5">
                  <span className="text-xs opacity-0 group-hover:opacity-100 transition-opacity">Investigate</span>
                  <ArrowUpRight className="w-4 h-4" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default RecentThreats;
