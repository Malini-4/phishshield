import React from 'react';
import { AlertOctagon, AlertTriangle, CheckCircle, HelpCircle } from 'lucide-react';
import { Verdict } from '../types';

interface StatusBadgeProps {
  verdict: Verdict | string;
  label: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ verdict, label }) => {
  const getBadgeClass = (v: string) => {
    switch (v) {
      case 'malicious':
        return 'badge-malicious';
      case 'suspicious':
        return 'badge-suspicious';
      case 'clean_no_findings':
        return 'badge-clean';
      case 'inconclusive':
      default:
        return 'badge-inconclusive';
    }
  };

  const getIcon = (v: string) => {
    switch (v) {
      case 'malicious':
        return <AlertOctagon size={16} aria-hidden="true" />;
      case 'suspicious':
        return <AlertTriangle size={16} aria-hidden="true" />;
      case 'clean_no_findings':
        return <CheckCircle size={16} aria-hidden="true" />;
      case 'inconclusive':
      default:
        return <HelpCircle size={16} aria-hidden="true" />;
    }
  };

  return (
    <span className={`status-badge ${getBadgeClass(verdict)}`} role="status">
      {getIcon(verdict)}
      <span>{label}</span>
    </span>
  );
};
