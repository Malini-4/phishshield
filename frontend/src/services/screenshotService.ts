import { request } from './apiClient';
import { AnalysisResult } from '../types';

export const screenshotService = {
  analyze: (file: File): Promise<AnalysisResult> => {
    const formData = new FormData();
    formData.append('file', file);
    return request<AnalysisResult>('/screenshot/analyze', {
      method: 'POST',
      body: formData,
    });
  },
};
