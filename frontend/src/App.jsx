import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  FileText, 
  BarChart3, 
  Cpu, 
  Settings as SettingsIcon,
  Shield,
  Clock
} from 'lucide-react';

import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import Analytics from './pages/Analytics';
import Models from './pages/Models';
import Settings from './pages/Settings';
import { getWsUrl } from './utils/api';

function App() {
  const location = useLocation();
  const [time, setTime] = useState(new Date());
  const [liveToast, setLiveToast] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // WebSocket Live Push Telemetry
  useEffect(() => {
    const wsUrl = getWsUrl() + '/ws/threats';

    let socket;
    try {
      socket = new WebSocket(wsUrl);
      socket.onopen = () => setWsConnected(true);
      socket.onclose = () => setWsConnected(false);
      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'pcap_analysis_completed') {
            setLiveToast(`PCAP Ingestion: ${data.threats_count} threats detected in ${data.filename}`);
            setTimeout(() => setLiveToast(null), 6000);
            window.dispatchEvent(new CustomEvent('soc-threat-created'));
          } else if (data.type === 'new_threat') {
            setLiveToast(`Live Threat Detected: [${data.threat?.attack_type}] from ${data.threat?.source_ip}`);
            setTimeout(() => setLiveToast(null), 6000);
            window.dispatchEvent(new CustomEvent('soc-threat-created'));
          }
        } catch (e) {
          console.error("WS Parse error:", e);
        }
      };
    } catch (_err) {
      console.warn("WebSocket initialization fallback to standard polling");
    }

    return () => {
      if (socket) socket.close();
    };
  }, []);

  const navItems = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Alerts', path: '/alerts', icon: ShieldAlert },
    { name: 'Logs', path: '/logs', icon: FileText },
    { name: 'Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Models (AI)', path: '/models', icon: Cpu },
    { name: 'Settings', path: '/settings', icon: SettingsIcon },
  ];

  const formatClock = (date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  };

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden text-slate-100 font-sans">
      
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
        
        {/* Sidebar Header / Logo */}
        <div>
          <div className="h-16 flex items-center gap-2.5 px-6 border-b border-slate-800 bg-slate-950/40">
            <div className="w-8 h-8 rounded-lg bg-emerald-600 flex items-center justify-center text-slate-100 shadow shadow-emerald-500/20">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">AI Cyber Threat</h1>
              <p className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest leading-none mt-0.5">SOC Monitor</p>
            </div>
          </div>
          
          {/* Nav Links */}
          <nav className="mt-6 px-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.name}
                  to={item.path}
                  className={`flex items-center gap-3.5 px-4 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-all group relative ${
                    isActive 
                      ? 'bg-slate-800/80 text-emerald-400 border border-slate-700/50 shadow shadow-slate-950/50' 
                      : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 transition-transform duration-200 group-hover:scale-105 ${isActive ? 'text-emerald-400' : 'text-slate-400 group-hover:text-slate-300'}`} />
                  <span>{item.name}</span>
                  {isActive && (
                    <span className="absolute left-0 top-1/4 bottom-1/4 w-1 rounded-r-md bg-emerald-500"></span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer info */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/20 text-center">
          <span className="text-[9px] uppercase font-bold text-slate-500 tracking-wider">Console Version v1.0.0</span>
        </div>
      </aside>

      {/* Main Panel */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* Top Header Bar */}
        <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0 relative">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
              SYSTEM MONITOR ACTIVE
            </span>
            {wsConnected && (
              <span className="hidden sm:inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-500/20">
                WS STREAM SYNC
              </span>
            )}
          </div>

          {/* Live Alert Toast Banner */}
          {liveToast && (
            <div className="absolute left-1/2 -translate-x-1/2 bg-rose-950/90 border border-rose-500/40 text-rose-200 px-4 py-1.5 rounded-full text-xs font-semibold shadow-lg shadow-rose-950/50 flex items-center gap-2 animate-bounce">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
              <span>{liveToast}</span>
            </div>
          )}
          
          <div className="flex items-center gap-4 text-xs font-semibold text-slate-400 bg-slate-950/40 border border-slate-800 px-4 py-2 rounded-lg">
            <Clock className="w-4 h-4 text-slate-500" />
            <span className="font-mono tracking-wider">{formatClock(time)}</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">{time.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}</span>
          </div>
        </header>

        {/* Content Container (Scrollable) */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/alerts" element={<Alerts showOnlyAttacks={true} />} />
            <Route path="/logs" element={<Alerts showOnlyAttacks={false} />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/models" element={<Models />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>

      </div>
    </div>
  );
}

export default App;
