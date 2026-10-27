import { request } from './apiClient';
import { AnalysisResult } from '../types';

export const urlService = {
  analyze: (url: string): Promise<AnalysisResult> => {
    return request<AnalysisResult>('/url/analyze', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },
};
