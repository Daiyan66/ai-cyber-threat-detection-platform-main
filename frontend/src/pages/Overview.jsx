import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, ShieldAlert, Cpu, Database } from 'lucide-react';

import SummaryCards from '../components/SummaryCards';
import DistributionChart from '../components/DistributionChart';
import RecentThreats from '../components/RecentThreats';
import Loader from '../components/Loader';
import ThreatDetailModal from '../components/ThreatDetailModal';
import GlobalThreatMap from '../components/GlobalThreatMap';
import { getApiUrl } from '../utils/api';

const Overview = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [summary, setSummary] = useState(null);
  const [distribution, setDistribution] = useState([]);
  const [recentThreats, setRecentThreats] = useState([]);
  
  const [selectedThreat, setSelectedThreat] = useState(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);
      const url = getApiUrl();
      
      const [summaryRes, distRes, threatsRes] = await Promise.all([
        axios.get(`${url}/threats/summary`),
        axios.get(`${url}/threats/distribution`),
        axios.get(`${url}/threats?limit=8`)
      ]);
      
      setSummary(summaryRes.data);
      setDistribution(distRes.data);
      setRecentThreats(threatsRes.data.items || threatsRes.data);
    } catch (err) {
      console.error("Failed to load dashboard metrics:", err);
      setError("Unable to connect to the backend security server. Ensure the FastAPI app is running on port 8000.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Read user-configured polling interval from localStorage (default 10s)
    const getIntervalMs = () => {
      const saved = localStorage.getItem('soc_polling_interval');
      return saved ? Math.max(3, parseInt(saved, 10)) * 1000 : 10000;
    };

    const refreshDataQuietly = () => {
      const url = getApiUrl();
      Promise.all([
        axios.get(`${url}/threats/summary`),
        axios.get(`${url}/threats/distribution`),
        axios.get(`${url}/threats?limit=8`)
      ]).then(([summaryRes, distRes, threatsRes]) => {
        setSummary(summaryRes.data);
        setDistribution(distRes.data);
        setRecentThreats(threatsRes.data.items || threatsRes.data);
      }).catch(console.error);
    };

    let timer = setInterval(refreshDataQuietly, getIntervalMs());

    const handleSettingsUpdated = () => {
      clearInterval(timer);
      refreshDataQuietly();
      timer = setInterval(refreshDataQuietly, getIntervalMs());
    };

    window.addEventListener('soc-settings-updated', handleSettingsUpdated);
    window.addEventListener('soc-threat-created', refreshDataQuietly);

    return () => {
      clearInterval(timer);
      window.removeEventListener('soc-settings-updated', handleSettingsUpdated);
      window.removeEventListener('soc-threat-created', refreshDataQuietly);
    };
  }, []);

  const handleUpdateStatus = (id, updatedThreat) => {
    // Update local threats list state if the updated threat is in our current recentThreats list
    setRecentThreats(prev => prev.map(t => t.id === id ? updatedThreat : t));
    
    // Refresh stats summary
    axios.get(`${getApiUrl()}/threats/summary`).then(res => setSummary(res.data)).catch(console.error);
    
    // Close modal
    setSelectedThreat(null);
  };

  if (loading && !summary) {
    return <Loader message="Connecting to SOC database and parsing threat logs..." />;
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center p-8 min-h-[400px]">
        <div className="bg-rose-950/20 border border-rose-500/20 p-6 rounded-xl max-w-md text-center shadow-lg">
          <ShieldAlert className="w-12 h-12 text-cyber-red mx-auto mb-4" />
          <h3 className="text-lg font-bold text-slate-200">Connection Failed</h3>
          <p className="text-sm text-slate-400 mt-2 leading-relaxed">{error}</p>
          <button 
            onClick={fetchData}
            className="mt-5 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold rounded-lg transition-all"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Top Banner (Status Panel) */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-5 glass-panel bg-slate-900/40 gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>SOC Monitoring Console</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">Analyzing network interface packets via Random Forest Classifier.</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="bg-slate-950 border border-slate-800/80 px-3.5 py-1.5 rounded-lg flex items-center gap-2">
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Neon DB: Connected</span>
          </div>
          <div className="bg-slate-950 border border-slate-800/80 px-3.5 py-1.5 rounded-lg flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">CIC-IDS2017: 99.5% Acc</span>
          </div>
          <div className="bg-slate-950 border border-slate-800/80 px-3.5 py-1.5 rounded-lg flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Monitor: ACTIVE</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && <SummaryCards summary={summary} />}

      {/* Global Geographic Threat Origin Map (Specification Module 3) */}
      <GlobalThreatMap />

      {/* Charts & Lists */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Attack distribution chart */}
        <div className="glass-panel p-5 lg:col-span-1 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-sky-400" />
              <span>Attack Distribution</span>
            </h2>
          </div>
          <DistributionChart data={distribution} />
        </div>

        {/* Right Column: Recent threats table */}
        <div className="glass-panel p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-cyber-orange" />
              <span>Live Intrusion Logs</span>
            </h2>
            <span className="text-[10px] font-bold text-slate-500 uppercase">Latest 8 Events</span>
          </div>
          <RecentThreats 
            threats={recentThreats} 
            onSelectThreat={setSelectedThreat} 
          />
        </div>

      </div>

      {/* Detail Modal / slide-over */}
      {selectedThreat && (
        <ThreatDetailModal 
          threat={selectedThreat} 
          onClose={() => setSelectedThreat(null)} 
          onUpdateStatus={handleUpdateStatus}
        />
      )}

    </div>
  );
};

export default Overview;
