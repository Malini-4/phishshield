import React, { useState } from 'react';
import { Smartphone, ShieldAlert, ArrowRight, ExternalLink } from 'lucide-react';
import { apkService } from '../services/apkService';
import { AnalysisResult } from '../types';
import { FileUpload } from '../components/FileUpload';
import { ResultSummary } from '../components/ResultSummary';
import { ScanProgress } from '../components/ScanProgress';
import { ErrorMessage } from '../components/ErrorMessage';
import { Link } from 'react-router-dom';

export const ApkAnalysisPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select an APK file to upload.');
      return;
    }

    setError(null);
    setLoading(true);
    setResult(null);

    try {
      const data = await apkService.analyze(selectedFile);
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'APK static analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-wrapper">
      <div className="page-header">
        <h1 className="page-title">Android APK Static Security Analysis</h1>
        <p className="page-subtitle">
          Deconstruct Android package archives offline. Identifies banking trojan signatures, SMS interception, dangerous device admin permissions, and embedded C2 domains.
        </p>
      </div>

      <div className="card">
        <form onSubmit={handleSubmit}>
          <FileUpload
            accept=".apk,application/vnd.android.package-archive"
            maxSizeMb={100}
            label="Upload Android APK Package"
            description="Supports standard Android .apk installation binaries"
            selectedFile={selectedFile}
            onFileSelect={setSelectedFile}
            disabled={loading}
          />

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading || !selectedFile}
            >
              <Smartphone size={18} />
              <span>Analyse APK</span>
            </button>
          </div>
        </form>

        <div
          style={{
            marginTop: '1.25rem',
            padding: '0.75rem 1rem',
            background: 'var(--bg-secondary)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-light)',
            fontSize: '0.82rem',
            color: 'var(--text-muted)',
            lineHeight: 1.45,
          }}
        >
          <strong>Static Safety Policy:</strong> Uploaded APK packages are <strong>never executed, installed, or emulated</strong> on this machine. Files are parsed strictly in memory or temporary isolated directories to extract AndroidManifest.xml and DEX string tables, and immediately purged.
        </div>
      </div>

      {error && <ErrorMessage message={error} onRetry={() => setError(null)} />}

      {loading && (
        <ScanProgress
          message="Parsing APK manifest and scanning DEX bytecode strings..."
          step="Evaluating trojan permission combinations & package spoofing..."
        />
      )}

      {result && <ResultSummary result={result} />}
    </div>
  );
};
