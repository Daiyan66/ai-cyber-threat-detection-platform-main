/**
 * Centralized API configuration for the AI Cyber Threat Detection Platform.
 * Supports dynamic runtime URL overrides via localStorage ('soc_api_url')
 * configured in the Settings modal, with fallback to Vite env or localhost.
 */

export const getApiUrl = () => {
  const url = localStorage.getItem('soc_api_url') || import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
  return url.replace(/\/+$/, '');
};

export const getWsUrl = () => {
  const httpUrl = getApiUrl();
  return httpUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
};

export const API_URL = getApiUrl();
