/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// User and Session Types
export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}

// SPF, DKIM, DMARC statuses
export type SecurityResult = 'PASS' | 'FAIL' | 'NONE' | 'TEMPERROR';

export interface SecurityStatus {
  result: SecurityResult;
  description: string;
  detail: string;
}

// Mail Relay Path Structure
export interface RelayStep {
  hop: number;
  from: string;
  by: string;
  with?: string;
  timestamp: string;
  ip?: string;
  delayMs?: number;
}

export interface EmailHeaders {
  from: string;
  to: string;
  subject: string;
  replyTo: string;
  returnPath: string;
  messageId: string;
  date: string;
  receivedSteps: RelayStep[];
  spf: SecurityStatus;
  dkim: SecurityStatus;
  dmarc: SecurityStatus;
  spfAlignment?: SecurityResult;
  dkimAlignment?: SecurityResult;
  dmarcAlignment?: SecurityResult;
  anomalies: string[];
}

export interface DomainMetadata {
  domain: string;
  age: string;
  creationDate: string;
  registrar: string;
  mxRecords: string[];
  txtRecords: string[];
  asn: string;
  country: string;
  reputationScore: number; // 0-100 (where 100 is safe, 0 is bad)
  ipAddress: string;
}

export interface UrlIntelligence {
  url: string;
  domain: string;
  reputation: 'safe' | 'suspicious' | 'malicious';
  category: string;
  redirectChain?: string[];
  hasSsl: boolean;
  indicators: string[];
}

export interface AttachmentIntelligence {
  filename: string;
  mimeType: string;
  sha256: string;
  size: number;
  isSuspicious: boolean;
  indicators: string[];
}

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  value: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  description: string;
}

export interface ThreatFactor {
  name: string;
  impact: number;
  isNegative: boolean; // true if it adds to risk, false if it reduces it
  description: string;
}

export interface ThreatScore {
  score: number; // 0 to 100
  level: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0 to 100%
  factors: ThreatFactor[];
}

export interface AiExplanation {
  summary: string;
  verdict: string;
  reasons: string[];
  recommendations: string[];
  isFallback?: boolean;
  engineName?: string;
}

// Main Email Analysis Result Schema
export interface EmailAnalysis {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  timestamp: string;
  fileName: string;
  fileSize: number;
  rawInput: string;
  headers: EmailHeaders;
  senderDomain: DomainMetadata;
  urls: UrlIntelligence[];
  attachments: AttachmentIntelligence[];
  iocs: IOC[];
  threatScore: ThreatScore;
  aiExplanation: AiExplanation;
  bodyText?: string;
  bodyHtml?: string;
}

// SOC General Statistics
export interface SocStats {
  totalAnalyzed: number;
  highRiskCount: number;
  suspiciousUrlsCount: number;
  maliciousAttachmentsCount: number;
  severityDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  threatActivityOverTime: {
    date: string;
    clean: number;
    suspicious: number;
    malicious: number;
  }[];
}
