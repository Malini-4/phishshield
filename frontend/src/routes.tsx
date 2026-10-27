import React from 'react';
import { RouteObject } from 'react-router-dom';
import { AppLayout } from './components/AppLayout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { UrlAnalysisPage } from './pages/UrlAnalysisPage';
import { ApkAnalysisPage } from './pages/ApkAnalysisPage';
import { SmsAnalysisPage } from './pages/SmsAnalysisPage';
import { ScreenshotAnalysisPage } from './pages/ScreenshotAnalysisPage';
import { HistoryPage } from './pages/HistoryPage';
import { ReportDetailsPage } from './pages/ReportDetailsPage';
import { AccountPage } from './pages/AccountPage';

export const routes: RouteObject[] = [
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/register',
    element: <RegisterPage />,
  },
  {
    path: '/',
    element: (
      <ProtectedRoute>
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'url', element: <UrlAnalysisPage /> },
      { path: 'apk', element: <ApkAnalysisPage /> },
      { path: 'sms', element: <SmsAnalysisPage /> },
      { path: 'screenshot', element: <ScreenshotAnalysisPage /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'history/:id', element: <ReportDetailsPage /> },
      { path: 'account', element: <AccountPage /> },
    ],
  },
];
