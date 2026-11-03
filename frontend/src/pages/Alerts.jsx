import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Filter, Search, ChevronLeft, ChevronRight, UploadCloud } from 'lucide-react';

import Loader from '../components/Loader';
import EmptyState from '../components/EmptyState';
import ThreatDetailModal from '../components/ThreatDetailModal';
import PcapUploadModal from '../components/PcapUploadModal';
import { getApiUrl } from '../utils/api';

const Alerts = ({ showOnlyAttacks = false }) => {
  const [loading, setLoading] = useState(true);
  const [threats, setThreats] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [showPcapModal, setShowPcapModal] = useState(false);
  
  // Filtering & Pagination state
  const [page, setPage] = useState(1);
  const [limit] = useState(15); // Show 15 logs per page
  
  const [severity, setSeverity] = useState('');
  const [attackType, setAttackType] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Debounce search input by 300ms
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      
      const params = {
        page,
        limit,
      };
      
      if (severity) params.severity = severity;
      if (attackType) params.attack_type = attackType;
      if (status) params.status = status;
      if (debouncedSearch) params.search = debouncedSearch;
      if (showOnlyAttacks) params.exclude_normal = true;
      
      const res = await axios.get(`${getApiUrl()}/threats`, { params });
      if (res.data && res.data.items) {
        setThreats(res.data.items);
        setTotal(res.data.total);
        setPages(res.data.pages);
      } else if (Array.isArray(res.data)) {
        setThreats(res.data);
        setTotal(res.data.length);
        setPages(1);
      }
    } catch (err) {
      console.error("Failed to load alerts list:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [page, severity, attackType, status, debouncedSearch, showOnlyAttacks]);

  useEffect(() => {
    const handleNewThreat = () => fetchThreats();
    window.addEventListener('soc-threat-created', handleNewThreat);
    return () => window.removeEventListener('soc-threat-created', handleNewThreat);
  }, []);

  // Reset page to 1 when filters change
  const handleFilterChange = (filterType, value) => {
    if (filterType === 'severity') setSeverity(value);
    if (filterType === 'attackType') setAttackType(value);
    if (filterType === 'status') setStatus(value);
    setPage(1);
  };

  const handleUpdateStatus = (id, updatedThreat) => {
    setThreats(prev => prev.map(t => t.id === id ? updatedThreat : t));
    setSelectedThreat(null);
  };

  const getSeverityBadge = (sev) => {
    switch (sev.toLowerCase()) {
      case 'critical': return 'bg-rose-500/10 text-cyber-red border-rose-500/20';
      case 'high': return 'bg-orange-500/10 text-cyber-orange border-orange-500/20';
      case 'medium': return 'bg-amber-500/10 text-cyber-yellow border-amber-500/20';
      default: return 'bg-slate-850 text-slate-400 border-slate-700';
    }
  };

  const getStatusBadge = (stat) => {
    switch (stat.toLowerCase()) {
      case 'resolved': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'investigating': return 'bg-sky-500/10 text-sky-400 border-sky-500/20';
      default: return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    }
  };

  const formatTimestamp = (isoString) => {
    const date = new Date(isoString);
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">
            {showOnlyAttacks ? "Intrusion Alarm Center" : "Network Flow Audit Logs"}
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            {showOnlyAttacks 
              ? "Investigate and filter classified network threat alerts." 
              : "Complete audit logs of benign and anomalous network activities."}
          </p>
        </div>
        <button
          onClick={() => setShowPcapModal(true)}
          className="flex items-center gap-2 px-3.5 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-bold transition-all shadow cursor-pointer self-start sm:self-auto"
        >
          <UploadCloud className="w-4 h-4" />
          <span>Ingest PCAP Capture</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="glass-panel p-4 bg-slate-900/40 flex flex-col md:flex-row gap-4 items-center justify-between">
        
        {/* IP Search */}
        <div className="relative w-full md:w-72">
          <Search className="absolute left-3.5 top-2.5 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP address or attack..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs focus:outline-none focus:border-slate-700 placeholder-slate-500 text-slate-200"
          />
        </div>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap gap-3 items-center w-full md:w-auto justify-end">
          
          {/* Severity */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-500 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Severity:
            </span>
            <select
              value={severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-slate-700 font-medium"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low / Normal</option>
            </select>
          </div>

          {/* Attack Type */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-500">Type:</span>
            <select
              value={attackType}
              onChange={(e) => handleFilterChange('attackType', e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-slate-700 font-medium"
            >
              <option value="">All</option>
              <option value="DDoS">DDoS</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Recon">Recon</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Malware">Malware</option>
              <option value="Normal">Normal</option>
            </select>
          </div>

          {/* Status */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-500">Status:</span>
            <select
              value={status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-slate-700 font-medium"
            >
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

        </div>
      </div>

      {/* Main Table Panel */}
      <div className="glass-panel overflow-hidden">
        {loading ? (
          <Loader message="Loading threat alarm history..." />
        ) : threats.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider bg-slate-950/20">
                  <th className="py-3.5 px-4">Timestamp</th>
                  <th className="py-3.5 px-4">Source IP</th>
                  <th className="py-3.5 px-4">Destination IP</th>
                  <th className="py-3.5 px-4">Attack Type</th>
                  <th className="py-3.5 px-4">Severity</th>
                  <th className="py-3.5 px-4">Confidence</th>
                  <th className="py-3.5 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-sm font-medium text-slate-200">
                {threats.map((threat) => (
                  <tr
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className="hover:bg-slate-900/40 transition-colors duration-150 cursor-pointer"
                  >
                    <td className="py-3 px-4 text-slate-400">{formatTimestamp(threat.timestamp)}</td>
                    <td className="py-3 px-4 font-mono">{threat.source_ip}</td>
                    <td className="py-3 px-4 font-mono">{threat.destination_ip}</td>
                    <td className="py-3 px-4">{threat.attack_type}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${getSeverityBadge(threat.severity)}`}>
                        {threat.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">{(threat.confidence * 100).toFixed(0)}%</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded-md text-xs font-bold border ${getStatusBadge(threat.status)}`}>
                        {threat.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Toolbar */}
        <div className="flex items-center justify-between border-t border-slate-800 px-4 py-3 bg-slate-950/20">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400">
              Displaying page <span className="font-semibold text-slate-200">{page}</span> of <span className="font-semibold text-slate-200">{pages}</span> ({total.toLocaleString()} total records)
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(p => Math.min(pages, p + 1))}
              disabled={page >= pages || loading}
              className="p-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Slide-over Investigation Drawer */}
      {selectedThreat && (
        <ThreatDetailModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onUpdateStatus={handleUpdateStatus}
        />
      )}

      {/* Direct PCAP Ingestion Modal */}
      <PcapUploadModal
        isOpen={showPcapModal}
        onClose={() => setShowPcapModal(false)}
        onPcapProcessed={() => {
          fetchThreats();
        }}
      />

    </div>
  );
};

export default Alerts;
