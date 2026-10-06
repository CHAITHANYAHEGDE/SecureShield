import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

export interface ProvenanceItem {
  provenance: 'MEASURED' | 'DERIVED' | 'SIMULATED';
}

export interface Prediction extends ProvenanceItem {
  label: 'malicious' | 'benign';
  confidence: number;
  model: string;
}

export interface ShapValue {
  feature: string;
  shap_contribution: number;
  abs_contribution: number;
  direction: 'malicious' | 'benign';
}

export interface Evidence extends ProvenanceItem {
  id: string;
  type: string;
  source: string;
  description: string;
  confidence: number;
}

export interface Correlation extends ProvenanceItem {
  evidence_ids: string[];
  rule: string;
  rationale: string;
}

export interface TimelineEvent extends ProvenanceItem {
  order: number;
  stage: string;
  description: string;
  evidence_ids: string[];
}

export interface MitreTechnique extends ProvenanceItem {
  tactic: string;
  technique_id: string;
  sub_technique: string;
  supporting_evidence_ids: string[];
  confidence: number;
  rule_id: string;
}

export interface RiskFactor {
  name: string;
  weight: number;
  value: number;
}

export interface Risk extends ProvenanceItem {
  score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: RiskFactor[];
}

export interface ResponsePlan {
  containment: string[];
  investigation: string[];
  recovery: string[];
}

export interface AnalysisResponse {
  prediction: Prediction;
  true_label?: string;
  features: Record<string, number>;
  shap: ShapValue[];
  evidence: Evidence[];
  correlation: Correlation[];
  timeline: TimelineEvent[];
  mitre: MitreTechnique[];
  risk: Risk;
  response: ResponsePlan;
}

export const fetchSamples = async () => {
  const { data } = await axios.get(`${API_BASE}/samples`);
  return data;
};

export const analyzeSample = async (sampleId: string): Promise<AnalysisResponse> => {
  const { data } = await axios.post(`${API_BASE}/analyze`, { sample_id: sampleId });
  return data;
};

export const fetchModels = async () => {
  const { data } = await axios.get(`${API_BASE}/models`);
  return data;
};

export const fetchRobustness = async () => {
  try {
    const { data } = await axios.get(`${API_BASE}/experiments/robustness`);
    return data;
  } catch (e) { return null; }
};

export const fetchAblation = async () => {
  try {
    const { data } = await axios.get(`${API_BASE}/experiments/ablation`);
    return data;
  } catch (e) { return null; }
};

export const fetchComparative = async () => {
  try {
    const { data } = await axios.get(`${API_BASE}/experiments/comparative`);
    return data;
  } catch (e) { return null; }
};
