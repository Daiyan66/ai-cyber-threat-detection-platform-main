import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Globe, Crosshair, RefreshCw } from 'lucide-react';
import { getApiUrl } from '../utils/api';

const GlobalThreatMap = () => {
  const [points, setPoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState(null);

  // Target Datacenter (San Francisco, CA)
  const target = { lat: 37.7749, lon: -122.4194, name: "US West SOC Datacenter" };

  const fetchMapData = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${getApiUrl()}/threats/map`);
      setPoints(res.data);
    } catch (err) {
      console.error("Failed to load map points:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMapData();
  }, []);

  // Convert Latitude / Longitude to SVG (Equirectangular projection)
  // Map dimensions: width=800, height=400
  const project = (lat, lon) => {
    const x = ((lon + 180) / 360) * 800;
    const y = ((90 - lat) / 180) * 400;
    return { x, y };
  };

  const targetCoords = project(target.lat, target.lon);

  const getColor = (attackType) => {
    switch (attackType) {
      case 'DDoS': return '#f43f5e';       // Rose/Red
      case 'Web Attack': return '#a855f7'; // Purple
      case 'Brute Force': return '#f97316';// Orange
      case 'PortScan': return '#fbbf24';   // Amber
      case 'Botnet': return '#06b6d4';     // Cyan
      default: return '#38bdf8';           // Sky Blue
    }
  };

  return (
    <div className="glass-panel p-5 bg-slate-900/40 relative overflow-hidden">
      
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-sky-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">
            Global Threat Origin Map (Animated Vectors)
          </h2>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-[10px] text-slate-400 font-semibold">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500"></span>DDoS</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500"></span>Brute Force</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-500"></span>Web Attack</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500"></span>PortScan</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-500"></span>Botnet</span>
          </div>
          <button
            onClick={fetchMapData}
            title="Refresh Map Coordinates"
            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* SVG Map Canvas */}
      <div className="w-full relative aspect-[2/1] bg-slate-950/80 rounded-xl border border-slate-800/80 overflow-hidden shadow-inner">
        
        {/* Subtle Background World Outline Grids */}
        <svg viewBox="0 0 800 400" className="w-full h-full">
          <defs>
            {/* Grid Pattern */}
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1e293b" strokeWidth="0.5" strokeOpacity="0.4" />
            </pattern>
            {/* Target Pulse Glow */}
            <radialGradient id="targetGlow">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
            </radialGradient>
          </defs>

          {/* Grid Background */}
          <rect width="800" height="400" fill="url(#grid)" />

          {/* Equator & Prime Meridian subtle guide markers */}
          <line x1="0" y1="200" x2="800" y2="200" stroke="#334155" strokeDasharray="2 4" strokeWidth="0.5" opacity="0.3" />
          <line x1="400" y1="0" x2="400" y2="400" stroke="#334155" strokeDasharray="2 4" strokeWidth="0.5" opacity="0.3" />

          {/* Attack Path Arc Curves */}
          {points.map((pt, idx) => {
            const origin = project(pt.lat, pt.lon);
            const color = getColor(pt.attack_type);
            
            // Calculate bezier control point for natural trajectory arc
            const dx = targetCoords.x - origin.x;
            const cx = origin.x + dx * 0.5;
            const cy = Math.min(origin.y, targetCoords.y) - Math.abs(dx) * 0.2;
            
            const pathD = `M ${origin.x} ${origin.y} Q ${cx} ${cy} ${targetCoords.x} ${targetCoords.y}`;

            return (
              <g key={`path-${idx}`} className="transition-opacity duration-300">
                {/* Background glow path */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={color}
                  strokeWidth="1.5"
                  strokeOpacity="0.25"
                  strokeDasharray="4 4"
                />
                {/* Streaming animated attack packet beam */}
                <path
                  d={pathD}
                  fill="none"
                  stroke={color}
                  strokeWidth="2"
                  strokeDasharray="6 30"
                  strokeDashoffset="0"
                  strokeLinecap="round"
                  className="animate-dash"
                />
              </g>
            );
          })}

          {/* Attacker Origin Nodes */}
          {points.map((pt, idx) => {
            const origin = project(pt.lat, pt.lon);
            const color = getColor(pt.attack_type);
            const radius = Math.min(8, Math.max(3.5, Math.log2(pt.count || 2) * 1.5));

            return (
              <g
                key={`node-${idx}`}
                onMouseEnter={() => setHovered(pt)}
                onMouseLeave={() => setHovered(null)}
                className="cursor-pointer group"
              >
                {/* Outer ping */}
                <circle
                  cx={origin.x}
                  cy={origin.y}
                  r={radius + 3}
                  fill={color}
                  opacity="0.2"
                  className="animate-ping"
                />
                {/* Solid core */}
                <circle
                  cx={origin.x}
                  cy={origin.y}
                  r={radius}
                  fill={color}
                  stroke="#0f172a"
                  strokeWidth="1.5"
                  className="transition-transform duration-200 group-hover:scale-125"
                />
              </g>
            );
          })}

          {/* Target Protected Datacenter Pin */}
          <g>
            <circle cx={targetCoords.x} cy={targetCoords.y} r="18" fill="url(#targetGlow)" />
            <circle cx={targetCoords.x} cy={targetCoords.y} r="4" fill="#10b981" stroke="#047857" strokeWidth="1.5" />
            <text
              x={targetCoords.x + 8}
              y={targetCoords.y + 3}
              fill="#10b981"
              fontSize="9"
              fontFamily="monospace"
              fontWeight="bold"
            >
              PROTECTED DC
            </text>
          </g>
        </svg>

        {/* Hover Tooltip Overlay */}
        {hovered && (
          <div className="absolute top-3 left-3 bg-slate-900/90 border border-slate-700/80 p-3 rounded-lg shadow-xl backdrop-blur-md pointer-events-none text-xs space-y-1 z-20">
            <div className="flex items-center gap-1.5 text-slate-200 font-bold">
              <Crosshair className="w-3.5 h-3.5 text-rose-400" />
              <span>{hovered.city}, {hovered.country}</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Vector: <span className="font-semibold text-slate-200" style={{ color: getColor(hovered.attack_type) }}>{hovered.attack_type}</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Severity: <span className="font-semibold text-slate-200 uppercase">{hovered.severity}</span>
            </div>
            <div className="text-[11px] text-slate-400">
              Aggregated Events: <span className="font-mono font-bold text-slate-200">{hovered.count}</span>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};

export default GlobalThreatMap;
