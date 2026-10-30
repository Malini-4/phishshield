import { request } from './apiClient';
import { CaseDetail, CaseSummary, CaseVerificationResult } from '../types';

export const caseService = {
  listCases: (): Promise<CaseSummary[]> => {
    return request<CaseSummary[]>('/cases');
  },

  getCase: (id: string): Promise<CaseDetail> => {
    return request<CaseDetail>(`/cases/${id}`);
  },

  verifyCase: (id: string): Promise<CaseVerificationResult> => {
    return request<CaseVerificationResult>(`/cases/${id}/verify`);
  },

  addNote: (id: string, text: string): Promise<any> => {
    return request<any>(`/cases/${id}/notes`, {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  },

  downloadPdf: async (id: string): Promise<void> => {
    const blob = await request<Blob>(`/cases/${id}/export.pdf`);
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishshield_case_${id.slice(0, 8)}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  },

  downloadJson: async (id: string): Promise<void> => {
    const data = await request<any>(`/cases/${id}/export.json`);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishshield_case_${id.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  },
};
