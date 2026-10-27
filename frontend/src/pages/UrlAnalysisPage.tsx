import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Globe, Shield, AlertCircle, Info } from 'lucide-react';
import { urlService } from '../services/urlService';
import { AnalysisResult } from '../types';
import { ResultSummary } from '../components/ResultSummary';
import { ScanProgress } from '../components/ScanProgress';
import { ErrorMessage } from '../components/ErrorMessage';

export const UrlAnalysisPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [urlInput, setUrlInput] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const prefill = searchParams.get('url');
    if (prefill) {
      setUrlInput(prefill);
    }
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = urlInput.trim();
    if (!target) {
      setError('Please enter a URL to analyse.');
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await urlService.analyze(target);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Please check the URL.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">URL Threat Analysis</h1>
        <p className="page-subtitle">
          Examine suspect links across banking, UPI, email, e-commerce, and credential theft kits using lexical heuristics, lookalike detection, and machine learning.
        </p>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="url-input" className="form-label">
              Enter Suspect URL or Link
            </label>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <input
                id="url-input"
                type="text"
                className="form-input"
                placeholder="e.g., https://netbanking-hdfc.trycloudflare.com/login.php or http://192.168.1.1/sbi"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                disabled={loading}
                style={{ flex: 1, minWidth: '280px' }}
                autoFocus
              />
              <button
                type="submit"
                className="btn-primary"
                disabled={loading || !urlInput.trim()}
              >
                <Globe size={18} />
                <span>Analyse URL</span>
              </button>
            </div>
          </div>
        </form>

        {/* Privacy & Inspection Disclosure */}
        <div
          style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            background: 'var(--bg-secondary)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-light)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.6rem',
            fontSize: '0.82rem',
            color: 'var(--text-muted)',
            lineHeight: 1.45,
          }}
        >
          <Info size={18} style={{ color: 'var(--primary)', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Strict Privacy Guarantee:</strong> The backend <strong>never visits, renders, or downloads content</strong> from the target URL. No DNS requests are performed to prevent IP exposure. Analysis is computed statically on URL syntax, brand lookalike algorithms, trained models, and optional local reputation feeds.
          </div>
        </div>
      </div>

      {error && <ErrorMessage message={error} onRetry={() => setError(null)} />}

      {loading && (
        <ScanProgress
          message="Inspecting URL structure, brand homographs, and model risk bands..."
          step="Running lexical extraction & offline security rules..."
        />
      )}

      {result && <ResultSummary result={result} />}
    </div>
  );
};
