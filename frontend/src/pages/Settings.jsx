import React, { useState } from 'react';
import { Settings as SettingsIcon, Sliders, Shield, Save } from 'lucide-react';
import { getApiUrl } from '../utils/api';

const Settings = () => {
  const [threshold, setThreshold] = useState(() => {
    return parseInt(localStorage.getItem('soc_threshold') || '85', 10);
  });
  const [interval, setIntervalVal] = useState(() => {
    return parseInt(localStorage.getItem('soc_polling_interval') || '10', 10);
  });
  const [apiUrl, setApiUrl] = useState(() => {
    return getApiUrl();
  });
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    localStorage.setItem('soc_threshold', threshold.toString());
    localStorage.setItem('soc_polling_interval', interval.toString());
    localStorage.setItem('soc_api_url', apiUrl.trim());
    
    // Broadcast event across app tabs / windows
    window.dispatchEvent(new Event('soc-settings-updated'));
    
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-xl">
      
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-slate-400" />
          <span>System Settings</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1">Configure threshold bounds, polling rates, and backend API routes.</p>
      </div>

      <div className="glass-panel p-6 bg-slate-900/40">
        <form onSubmit={handleSave} className="space-y-5">
          
          {/* Threshold slider */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Sliders className="w-4 h-4 text-sky-400" />
              <span>Anomaly Alarm Threshold ({threshold}%)</span>
            </label>
            <input
              type="range"
              min="50"
              max="99"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              className="w-full bg-slate-850 h-1.5 rounded-lg appearance-none cursor-pointer accent-emerald-500"
            />
            <span className="text-[10px] text-slate-500 block">Threat alerts with classification confidence below this value will not trigger high severity notifications.</span>
          </div>

          {/* Refresh Interval */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span>Log Polling Interval (Seconds)</span>
            </label>
            <input
              type="number"
              min="1"
              max="60"
              value={interval}
              onChange={(e) => setIntervalVal(parseInt(e.target.value || '1', 10))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700"
            />
            <span className="text-[10px] text-slate-500 block">Rate at which the dashboard pulls active logs from the server database (default is 10s).</span>
          </div>

          {/* API URL */}
          <div className="space-y-2">
            <label className="text-xs font-bold uppercase tracking-wider text-slate-400">
              <span>Backend API Server URL</span>
            </label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-slate-700 font-mono"
            />
            <span className="text-[10px] text-slate-500 block">Target server endpoint where threat logs are hosted.</span>
          </div>

          {/* Save Button */}
          <div className="pt-2">
            <button
              type="submit"
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-100 px-4 py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all shadow-md"
            >
              <Save className="w-4 h-4" />
              <span>{saved ? "Settings Applied!" : "Save Modifications"}</span>
            </button>
          </div>

        </form>
      </div>

    </div>
  );
};

export default Settings;
